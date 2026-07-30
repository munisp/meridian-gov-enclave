package main

// Nigerian states + FCT (ISO 3166-2:NG codes), seeded into the authority registry.
var nigerianStates = []struct {
	Code string
	Name string
	IRS  string
}{
	{"NG-AB", "Abia", "Abia State Internal Revenue Service"},
	{"NG-AD", "Adamawa", "Adamawa State Internal Revenue Service"},
	{"NG-AK", "Akwa Ibom", "Akwa Ibom State Internal Revenue Service"},
	{"NG-AN", "Anambra", "Anambra State Internal Revenue Service"},
	{"NG-BA", "Bauchi", "Bauchi State Internal Revenue Service"},
	{"NG-BY", "Bayelsa", "Bayelsa State Internal Revenue Service"},
	{"NG-BE", "Benue", "Benue State Internal Revenue Service"},
	{"NG-BO", "Borno", "Borno State Internal Revenue Service"},
	{"NG-CR", "Cross River", "Cross River State Internal Revenue Service"},
	{"NG-DE", "Delta", "Delta State Internal Revenue Service"},
	{"NG-EB", "Ebonyi", "Ebonyi State Internal Revenue Service"},
	{"NG-ED", "Edo", "Edo State Internal Revenue Service"},
	{"NG-EK", "Ekiti", "Ekiti State Internal Revenue Service"},
	{"NG-EN", "Enugu", "Enugu State Internal Revenue Service"},
	{"NG-GO", "Gombe", "Gombe State Internal Revenue Service"},
	{"NG-IM", "Imo", "Imo State Internal Revenue Service"},
	{"NG-JI", "Jigawa", "Jigawa State Internal Revenue Service"},
	{"NG-KD", "Kaduna", "Kaduna State Internal Revenue Service"},
	{"NG-KN", "Kano", "Kano State Internal Revenue Service"},
	{"NG-KT", "Katsina", "Katsina State Internal Revenue Service"},
	{"NG-KE", "Kebbi", "Kebbi State Internal Revenue Service"},
	{"NG-KO", "Kogi", "Kogi State Internal Revenue Service"},
	{"NG-KW", "Kwara", "Kwara State Internal Revenue Service"},
	{"NG-LA", "Lagos", "Lagos Internal Revenue Service (LIRS)"},
	{"NG-NA", "Nasarawa", "Nasarawa State Internal Revenue Service"},
	{"NG-NI", "Niger", "Niger State Internal Revenue Service"},
	{"NG-OG", "Ogun", "Ogun State Internal Revenue Service"},
	{"NG-ON", "Ondo", "Ondo State Internal Revenue Service"},
	{"NG-OS", "Osun", "Osun State Internal Revenue Service"},
	{"NG-OY", "Oyo", "Oyo State Internal Revenue Service"},
	{"NG-PL", "Plateau", "Plateau State Internal Revenue Service"},
	{"NG-RI", "Rivers", "Rivers State Internal Revenue Service"},
	{"NG-SO", "Sokoto", "Sokoto State Internal Revenue Service"},
	{"NG-TA", "Taraba", "Taraba State Internal Revenue Service"},
	{"NG-YO", "Yobe", "Yobe State Internal Revenue Service"},
	{"NG-ZA", "Zamfara", "Zamfara State Internal Revenue Service"},
	{"NG-FC", "FCT", "FCT Internal Revenue Service (FCT-IRS)"},
}
