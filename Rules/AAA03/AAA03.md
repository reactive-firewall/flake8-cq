# AAA03: expected 1 blank line before Act block, found none.

For tests that have an Arrange block, there must be a blank line between the Arrange and Act
blocks, but Flake8-AAA could not find one.

## Prerequisites

This rule works best with pycodestyle’s `E303` rule enabled because it ensures that there are not
multiple blank lines between the blocks.

If test code is formatted with Black, then it’s best to set `large` Act block style.

## Problematic code

```python
def test_simple(hello_world_path: pathlib.Path) -> None:
    with open(hello_world_path) as f:
        result = f.read()

    assert result == 'Hello World!\n'
```

## Correct code

Since the `open()` context manager is part of the Arrange block, create space between it and the
`result =` Act block.

```python
def test_simple(hello_world_path: pathlib.Path) -> None:
    with open(hello_world_path) as f:

        result = f.read()

    assert result == 'Hello World!\n'
```

Alternatively, if you want the context manager to be treated as part of the Act block,
the `large` Act block style as mentioned above.

## Rationale

This blank line creates separation between the test’s Arrange and Act blocks and makes the Act
block easy to spot.

## See Also

* [Flake-aaa AAA03](https://flake8-aaa.readthedocs.io/en/stable/error_codes/AAA03-expected-1-blank-line-before-act-block.html)
* [Arrange-Act-Assert: A Pattern for Writing Good Tests](https://automationpanda.com/2020/07/07/arrange-act-assert-a-pattern-for-writing-good-tests/)
* [Large Act Block-Style](https://flake8-aaa.readthedocs.io/en/stable/options.html#large-act-block-style)
