"""WhatsApp e-invoice bot (Feature I4): conversational NRS e-invoicing over
the Meta Cloud API channel, calling the compliance-suite einvoicing service.

Conversation design follows the nactp whatsapp-bot prototype (guided,
step-by-step collection with explicit confirm), hardened to enclave rules:

- Authz: the wa_id must be bound to a TIN (wa_onboarding binding / seeded
  session TIN). Unbound numbers get enrollment instructions and can NEVER
  issue an invoice.
- Issue flow: menu -> buyer TIN -> amount (NGN) -> description -> confirm.
  Amounts are parsed to integer kobo (<=2dp, >0); the NRS wire payload
  carries decimal NGN derived from kobo (the service converts back to kobo
  round-half-up — no float noise is ever produced here).
- Status flow: "status" -> IRN prompt -> POST /v1/invoices/nrs {"irn": ...}
  (the service's idempotent IRN lookup replays the stored invoice).
- Idempotency: the issue flow's Idempotency-Key is derived from the wa_id +
  the Meta message id that STARTED the flow (Meta message ids are stable
  across redelivery) and pinned in the session for the whole conversation —
  a double-confirm or webhook redelivery can never create a second invoice.
- Honesty: any upstream failure (network, non-2xx, malformed response) yields
  an honest error reply; a confirmation/IRN is NEVER fabricated.
- Fail-closed gate: HERMES_EINVOICING_URL / HERMES_EINVOICING_SERVICE_TOKEN
  unset -> the feature is DISABLED with an explicit log line and the bot
  tells the user the feature is unavailable (same behaviour in prod and dev;
  in prod the missing config is logged at error level).
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Optional

from .wa_onboarding import mask_tin, valid_tin

log = logging.getLogger("hermes.whatsapp.invoice")

INVOICE_PATH = "/v1/invoices/nrs"
IRN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{2,98}$")
_AMOUNT_RE = re.compile(r"^(?:NGN\s*|N\s*|₦\s*)?([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*$",
                        re.IGNORECASE)
_CANCEL_WORDS = {"cancel", "stop", "quit", "exit"}
_MENU_WORDS = {"invoice", "e-invoice", "einvoice", "einvoicing", "invoicing"}
# NOTE: bare "status" is deliberately NOT a trigger — the existing channel
# command STATUS reports the TIN-binding state (wa_onboarding).
_STATUS_WORDS = {"invoice status", "e-invoice status", "irn"}

# Session-state keys (inside the existing wa session dict).
_ST_STATE = "inv_state"          # None | menu | buyer_tin | amount | desc | confirm | status_irn
_ST_BUYER = "inv_buyer_tin"
_ST_KOBO = "inv_amount_kobo"
_ST_DESC = "inv_description"
_ST_IDEM = "inv_idempotency_key"

BTN_NEW = "inv_new"
BTN_STATUS = "inv_status"
BTN_CONFIRM = "inv_confirm_go"
BTN_CANCEL = "inv_confirm_no"

MENU_TEXT = (
    "NRS e-Invoice (WhatsApp)\n\n"
    "What would you like to do?\n\n"
    "1. Issue a new e-invoice\n"
    "2. Check invoice status by IRN\n\n"
    "Reply 1 or 2 (or CANCEL to exit).")

UNAVAILABLE_TEXT = (
    "The e-invoice service is currently unavailable on this channel. "
    "Please try again later or use the NRS merchant portal.")

UNBOUND_TEXT = (
    "To issue or check e-invoices here, this WhatsApp number must first be "
    "linked to your business TIN. Reply with your TIN (format NNNNNNNN-NNNN) "
    "to enrol; we'll verify it with a one-time code.")


class EinvoicingError(RuntimeError):
    """Upstream einvoicing call failed (network / non-2xx / bad body).
    Surfaced to the user as an honest error — never a fake confirmation."""


def _urllib_transport(url: str, headers: dict[str, str], body: bytes,
                      timeout_s: float) -> dict[str, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec - env-configured host
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


class EinvoicingClient:
    """HTTP client for the einvoicing service's NRS endpoints.

    Transport is injectable for tests: fn(url, headers, body, timeout_s)."""

    def __init__(self, base_url: str = "", service_token: str = "",
                 timeout_s: float = 15.0, transport: Optional[Callable] = None):
        self.base_url = base_url.rstrip("/")
        self.service_token = service_token
        self.timeout_s = timeout_s
        self.transport = transport or _urllib_transport

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.service_token)

    def _post_nrs(self, payload: dict[str, Any],
                  idempotency_key: str = "") -> dict[str, Any]:
        if not self.enabled:
            raise EinvoicingError("einvoicing client is disabled (missing "
                                  "HERMES_EINVOICING_URL / service token)")
        headers = {"content-type": "application/json",
                   "authorization": f"Bearer {self.service_token}"}
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        url = self.base_url + INVOICE_PATH
        body = json.dumps(payload).encode()
        try:
            return self.transport(url, headers, body, self.timeout_s)
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                raw = e.read().decode()
                detail = json.loads(raw).get("detail", "")[:200]
            except Exception:  # noqa: BLE001 - best-effort detail only
                pass
            raise EinvoicingError(
                f"einvoicing service rejected the request: HTTP {e.code}"
                + (f" ({detail})" if detail else "")) from e
        except EinvoicingError:
            raise
        except Exception as e:  # noqa: BLE001 - timeout/network, fail closed
            raise EinvoicingError(
                f"einvoicing service unreachable: {type(e).__name__}") from e

    def create_invoice(self, *, supplier_tin: str, buyer_tin: str,
                       amount_kobo: int, description: str,
                       idempotency_key: str) -> dict[str, Any]:
        """POST /v1/invoices/nrs with an NRS-schema commercial invoice.
        Decimal NGN on the wire is derived from integer kobo (exact 2dp)."""
        amount_ngn = amount_kobo / 100  # exact: kobo is an int, 2dp max
        payload = {
            "business_id": supplier_tin,
            "issue_date": date.today().isoformat(),
            "invoice_type_code": "380",          # commercial invoice
            "document_currency_code": "NGN",
            "invoice_kind": "B2B",
            "buyer_reference": idempotency_key[:64],
            "note": description,
            "accounting_supplier_party": {
                "party_name": f"Supplier {mask_tin(supplier_tin)}",
                "tin": supplier_tin,
            },
            "accounting_customer_party": {
                "party_name": f"Buyer {mask_tin(buyer_tin)}",
                "tin": buyer_tin,
            },
            "invoice_line": [{
                "invoiced_quantity": 1,
                "line_extension_amount": amount_ngn,
                "item": {"name": description[:80] or "Goods/Services",
                         "description": description},
                "price": {"price_amount": amount_ngn, "base_quantity": 1},
            }],
            "legal_monetary_total": {
                "line_extension_amount": amount_ngn,
                "tax_exclusive_amount": amount_ngn,
                "tax_inclusive_amount": amount_ngn,
                "payable_amount": amount_ngn,
            },
        }
        return self._post_nrs(payload, idempotency_key=idempotency_key)

    def status_by_irn(self, irn: str) -> dict[str, Any]:
        """Idempotent IRN lookup: POST {"irn": ...} replays the stored
        invoice (service-side GetByIRN before schema validation)."""
        return self._post_nrs({"irn": irn})


def parse_amount_kobo(text: str) -> Optional[int]:
    """Parse a user-entered NGN amount to integer kobo. Accepts commas,
    optional ₦/N/NGN prefix, max 2 decimals. Returns None when invalid."""
    m = _AMOUNT_RE.match(text.strip())
    if not m:
        return None
    digits = m.group(1).replace(",", "")
    try:
        dec = Decimal(digits)
    except InvalidOperation:
        return None
    if dec <= 0 or dec > Decimal("999999999.99"):
        return None
    return int(dec * 100)  # <=2dp guaranteed by the regex -> exact


def _fmt_naira(kobo: int) -> str:
    return f"₦{kobo / 100:,.2f}"


def _qr_reference(resp: dict[str, Any]) -> str:
    qr = resp.get("qr") or {}
    payload = qr.get("payload", "")
    if payload:
        return payload
    irn = resp.get("irn", "")
    return f"IRN: {irn}" if irn else ""


class InvoiceFlow:
    """Stateful WhatsApp e-invoice conversation over the shared session dict.

    handle() returns True when the message was consumed by the invoice
    feature (menu, prompts, confirm, status); False => fall through to the
    normal onboarding/agent path."""

    def __init__(self, client: EinvoicingClient, wa, save):
        self.client = client
        self.wa = wa                # WhatsAppClient (send_text/send_buttons)
        self._save = save           # fn(wa_id, session_dict)

    # -- helpers ----------------------------------------------------------
    def _reset(self, st: dict[str, Any]) -> None:
        for k in (_ST_STATE, _ST_BUYER, _ST_KOBO, _ST_DESC, _ST_IDEM):
            st.pop(k, None)

    def _enabled(self, wa_id: str) -> bool:
        if self.client.enabled:
            return True
        log.error("whatsapp invoice: feature DISABLED (missing "
                  "HERMES_EINVOICING_URL/HERMES_EINVOICING_SERVICE_TOKEN); "
                  "wa_id=%s told feature unavailable", wa_id)
        self.wa.send_text(wa_id, UNAVAILABLE_TEXT)
        return False

    def _menu(self, wa_id: str, st: dict[str, Any]) -> None:
        st[_ST_STATE] = "menu"
        self._save(wa_id, st)
        self.wa.send_buttons(wa_id, MENU_TEXT,
                             [(BTN_NEW, "New invoice"),
                              (BTN_STATUS, "Check status")])

    # -- entry points -----------------------------------------------------
    def handle_button(self, wa_id: str, st: dict[str, Any],
                      button_id: str, msg_id: str) -> bool:
        if button_id == BTN_NEW:
            return self._start_issue(wa_id, st, msg_id)
        if button_id == BTN_STATUS:
            return self._start_status(wa_id, st)
        if button_id == BTN_CONFIRM and st.get(_ST_STATE) == "confirm":
            return self._do_issue(wa_id, st)
        if button_id == BTN_CANCEL and st.get(_ST_STATE) is not None:
            self._reset(st)
            self._save(wa_id, st)
            self.wa.send_text(wa_id, "Invoice flow cancelled.")
            return True
        return False

    def handle_text(self, wa_id: str, st: dict[str, Any],
                    text: str, msg_id: str) -> bool:
        cmd = text.strip()
        lower = cmd.lower()
        state = st.get(_ST_STATE)

        if state is not None and lower in _CANCEL_WORDS:
            self._reset(st)
            self._save(wa_id, st)
            self.wa.send_text(wa_id, "Invoice flow cancelled. Send INVOICE "
                                     "to start again.")
            return True

        if lower in _MENU_WORDS:
            return self._menu_guard(wa_id, st)
        if lower in _STATUS_WORDS:
            return self._start_status(wa_id, st)

        if state == "menu":
            if cmd == "1":
                return self._start_issue(wa_id, st, msg_id)
            if cmd == "2":
                return self._start_status(wa_id, st)
            self._menu(wa_id, st)
            return True

        if state == "buyer_tin":
            if not valid_tin(cmd):
                self.wa.send_text(wa_id, "That TIN is not valid (NRS format "
                                         "NNNNNNNN-NNNN with check digit). "
                                         "Please re-enter the buyer's TIN, or "
                                         "CANCEL to exit.")
                return True
            st[_ST_BUYER] = cmd
            st[_ST_STATE] = "amount"
            self._save(wa_id, st)
            self.wa.send_text(wa_id, "Step 2 of 3 — Amount.\n\n"
                                     "Enter the invoice amount in Naira "
                                     "(e.g. 150000 or 2500.50):")
            return True

        if state == "amount":
            kobo = parse_amount_kobo(cmd)
            if kobo is None:
                self.wa.send_text(wa_id, "I couldn't read that amount. Enter "
                                         "a positive Naira amount with at "
                                         "most 2 decimals (e.g. 150000 or "
                                         "2500.50), or CANCEL to exit.")
                return True
            st[_ST_KOBO] = kobo
            st[_ST_STATE] = "desc"
            self._save(wa_id, st)
            self.wa.send_text(wa_id, "Step 3 of 3 — Description.\n\n"
                                     "What is this invoice for? (short "
                                     "description of the goods/services):")
            return True

        if state == "desc":
            desc = cmd[:500]
            if len(desc) < 3:
                self.wa.send_text(wa_id, "Please give a short description "
                                         "(at least 3 characters), or CANCEL "
                                         "to exit.")
                return True
            st[_ST_DESC] = desc
            st[_ST_STATE] = "confirm"
            self._save(wa_id, st)
            summary = (
                "Please confirm the e-invoice:\n\n"
                f"Buyer TIN: {mask_tin(st[_ST_BUYER])}\n"
                f"Amount: {_fmt_naira(st[_ST_KOBO])}\n"
                f"Description: {desc}\n\n"
                "Confirm to issue via NRS e-invoicing.")
            self.wa.send_buttons(wa_id, summary,
                                 [(BTN_CONFIRM, "Confirm"),
                                  (BTN_CANCEL, "Cancel")])
            return True

        if state == "confirm":
            self.wa.send_text(wa_id, "Please tap Confirm or Cancel above "
                                     "(or reply CANCEL to exit).")
            return True

        if state == "status_irn":
            if not IRN_RE.match(cmd):
                self.wa.send_text(wa_id, "That doesn't look like an IRN "
                                         "(format <InvoiceNumber>-<ServiceID>-"
                                         "<YYYYMMDD>). Please re-enter it, or "
                                         "CANCEL to exit.")
                return True
            return self._do_status(wa_id, st, cmd)

        return False

    # -- flow actions -----------------------------------------------------
    def _menu_guard(self, wa_id: str, st: dict[str, Any]) -> bool:
        if not self._enabled(wa_id):
            return True
        if not st.get("tin"):
            self.wa.send_text(wa_id, UNBOUND_TEXT)
            return True
        self._menu(wa_id, st)
        return True

    def _start_issue(self, wa_id: str, st: dict[str, Any], msg_id: str) -> bool:
        if not self._enabled(wa_id):
            return True
        if not st.get("tin"):
            self.wa.send_text(wa_id, UNBOUND_TEXT)
            return True
        self._reset(st)
        # Durable idempotency key: conversation (wa_id) + the stable Meta
        # message id that started this flow. Pinned for the whole flow so a
        # redelivery or double-confirm can never create a second invoice.
        st[_ST_IDEM] = f"wa-invoice:{wa_id}:{msg_id}"
        st[_ST_STATE] = "buyer_tin"
        self._save(wa_id, st)
        self.wa.send_text(wa_id, "New e-invoice — Step 1 of 3.\n\n"
                                 "Enter the buyer's TIN "
                                 "(format NNNNNNNN-NNNN):")
        return True

    def _start_status(self, wa_id: str, st: dict[str, Any]) -> bool:
        if not self._enabled(wa_id):
            return True
        if not st.get("tin"):
            self.wa.send_text(wa_id, UNBOUND_TEXT)
            return True
        self._reset(st)
        st[_ST_STATE] = "status_irn"
        self._save(wa_id, st)
        self.wa.send_text(wa_id, "Enter the invoice IRN "
                                 "(<InvoiceNumber>-<ServiceID>-<YYYYMMDD>):")
        return True

    def _do_issue(self, wa_id: str, st: dict[str, Any]) -> bool:
        supplier_tin = st.get("tin", "")
        buyer_tin = st.get(_ST_BUYER, "")
        kobo = st.get(_ST_KOBO)
        desc = st.get(_ST_DESC, "")
        idem = st.get(_ST_IDEM, "")
        if not (supplier_tin and buyer_tin and kobo and desc and idem):
            self._reset(st)
            self._save(wa_id, st)
            self.wa.send_text(wa_id, "That invoice session has expired. Send "
                                     "INVOICE to start again.")
            return True
        try:
            resp = self.client.create_invoice(
                supplier_tin=supplier_tin, buyer_tin=buyer_tin,
                amount_kobo=int(kobo), description=desc,
                idempotency_key=idem)
        except EinvoicingError as e:
            # Honest failure: the flow is reset; NO confirmation is faked.
            self._reset(st)
            self._save(wa_id, st)
            log.error("whatsapp invoice: issuance failed wa_id=%s: %s",
                      wa_id, e)
            self.wa.send_text(wa_id, "We could NOT issue the invoice: the "
                                     "e-invoicing service reported an error "
                                     f"({e}). No invoice was created. Send "
                                     "INVOICE to try again.")
            return True
        self._reset(st)
        self._save(wa_id, st)
        irn = resp.get("irn", "")
        status = resp.get("status", "")
        ref = _qr_reference(resp)
        replay = " (already issued — existing invoice returned)" \
            if resp.get("idempotent_replay") else ""
        self.wa.send_text(
            wa_id,
            f"E-invoice issued{replay}.\n\n"
            f"IRN: {irn}\n"
            f"Status: {status}\n"
            f"Amount: {_fmt_naira(int(kobo))}\n\n"
            f"NRS verification reference:\n{ref}\n\n"
            "Keep the IRN for your records; send IRN to check its status later.")
        log.info("whatsapp invoice: issued wa_id=%s irn=%s status=%s",
                 wa_id, irn, status)
        return True

    def _do_status(self, wa_id: str, st: dict[str, Any], irn: str) -> bool:
        try:
            resp = self.client.status_by_irn(irn)
        except EinvoicingError as e:
            self._reset(st)
            self._save(wa_id, st)
            log.error("whatsapp invoice: status lookup failed wa_id=%s "
                      "irn=%s: %s", wa_id, irn, e)
            self.wa.send_text(wa_id, "We could not retrieve that invoice "
                                     f"({e}). Please check the IRN and try "
                                     "again later.")
            return True
        self._reset(st)
        self._save(wa_id, st)
        found_irn = resp.get("irn", "")
        if not found_irn:
            self.wa.send_text(wa_id, "No invoice was found for that IRN. "
                                     "Check the number and send IRN to "
                                     "try again.")
            return True
        ref = _qr_reference(resp)
        self.wa.send_text(
            wa_id,
            f"IRN: {found_irn}\n"
            f"Status: {resp.get('status', '')}\n"
            f"Payment status: {resp.get('payment_status', '')}\n"
            + (f"NRS verification reference:\n{ref}" if ref else ""))
        return True
