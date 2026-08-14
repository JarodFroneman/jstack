# tinyxml2 numeric character-reference replay

In a debug build, parsing an out-of-range decimal character reference such as
`&#5000000000;` aborts on an assertion. Handle malformed and out-of-range
numeric references without an assertion, memory error, or unrelated parser
regression. Preserve valid decimal and hexadecimal references. Keep the change
within the parser implementation and return debug-suite evidence.
