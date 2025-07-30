# AAA02: multiple Act blocks found in test.

There must be one and only one Act block in every test but Flake8-AAA found more than one
potential Act block. This error is usually triggered when a test contains more than one
`result =` statement or more than one line marked `# act`. Multiple Act blocks create ambiguity
and raise this error code.

## Resolution

Split the failing test into multiple tests. Where there is complicated or reused set-up code then
apply the DRY principle and extract the reused code into one or more fixtures.

## See Also

* [Flake-aaa AAA02](https://flake8-aaa.readthedocs.io/en/stable/error_codes/AAA02-multiple-act-blocks-found-in-test.html)
* [Arrange-Act-Assert: A Pattern for Writing Good Tests](https://automationpanda.com/2020/07/07/arrange-act-assert-a-pattern-for-writing-good-tests/)
* [DRY](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself)
