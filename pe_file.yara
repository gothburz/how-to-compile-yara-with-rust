rule is_pe
{
	meta:
		description = "Detects 'MZ header'"
		author = "Peter Girnus"
        web = "https://www.petergirnus.com/blog"

	condition:
		uint16(0) == 0x5a4d
}