package lib

import "testing"

func TestSemverCompare(t *testing.T) {
	runHelperCases(t, nil, []helperCase{
		{`semver.compare("8.0.35", "8.0.35")`, 0, nil},
		{`semver.compare("8.0.35", "8.0.4")`, 1, nil},
		{`semver.compare("8.0.4", "8.0.35")`, -1, nil},
		{`semver.compare("v1.2.3", "1.2.3")`, 0, nil},
		{`semver.compare("v1.2.3", "v1.2.4")`, -1, nil},
		{`semver.compare("8.0", "8.0.0")`, 0, nil}, // missing segment = 0
		{`semver.compare("8", "8.0.1")`, -1, nil},
		{`semver.compare("08.0", "8.0")`, 0, nil}, // numeric, not byte-wise
		{`semver.compare("10.0", "9.9")`, 1, nil},
		{`semver.compare("99999999999999999999999.1", "99999999999999999999998.9")`, 1, nil},
		{`semver.compare("5.7.mysql_aurora.2.11.2", "5.7.mysql_aurora.2.11.10")`, -1, nil},
		{`semver.compare("5.7.mysql_aurora.2.11.2", "5.7.mysql_aurora.2.11.2")`, 0, nil},
		{`semver.compare("5.7.mysql_aurora.3.0.0", "5.7.mysql_aurora.2.11.2")`, 1, nil},
		{`semver.compare("8.0.mysql_aurora.3.04.0", "8.0.mysql_aurora.3.4.0")`, 0, nil},
		{`semver.compare("1.0-rc1", "1.0-rc2")`, -1, nil}, // split on -
		{`semver.compare("1.0-b", "1.0-a")`, 1, nil},      // byte-wise
		{`semver.compare("1.0.mysql", "1.0.0")`, 1, nil},  // "mysql" vs "0" byte-wise
		{`semver.compare("1.0.A", "1.0.a")`, -1, nil},     // byte-wise, case-sensitive
		{`semver.compare("", "1.0")`, nil, ErrInvalid},
		{`semver.compare("1.0", "")`, nil, ErrInvalid},
		{`semver.compare("v", "1.0")`, nil, ErrInvalid},
		{`semver.compare("1..0", "1.0")`, nil, ErrInvalid},
		{`semver.compare("1.0.", "1.0")`, nil, ErrInvalid},
		{`semver.compare("1.0", "-1.0")`, nil, ErrInvalid},
		{`semver.compare(" 1.0", "1.0")`, nil, ErrInvalid}, // whitespace: leading
		{`semver.compare("1.0 ", "1.0")`, nil, ErrInvalid}, // trailing
		{`semver.compare("1. 0", "1.0")`, nil, ErrInvalid}, // internal
		{`semver.compare("1.0", "1.0\n")`, nil, ErrInvalid},
		{`semver.compare("1.0", "\t1.0")`, nil, ErrInvalid},
		{`semver.compare("1.0", "1.0\u00a0")`, nil, ErrInvalid}, // no-break space
		{`semver.compare("v 1.0", "1.0")`, nil, ErrInvalid},
	})
}
