# 100 Days of Yara in 2024: Day 03
Time for some quality of life work in YARA-X! 

## Motivation
If you've written rules with a large number or two, I'm sure you've had to count the digits in it at one point or another to make sure its the right number. 

Some languages, like Rust, allow you to add underscores to numbers to improve readability and clarity like so:

```rust
  // Use underscores to improve readability!
  println!("One million is written as {}", 1_000_000u32);
```

You can find the documentation about the above [here](https://doc.rust-lang.org/rust-by-example/primitives/literals.html#:~:text=Underscores%20can%20be%20inserted%20in,The%20associated%20type%20is%20f64%20.).

There's not a lot of complex motivation behind this change other than there already being an issue ([#14](https://github.com/VirusTotal/yara-x/issues/14)) for it by Victor on GitHub, and it just making things nicer to look at.
## Implementation
In YARA-X, the parser used for the rules and grammar is the [`pest`](https://pest.rs/) crate. Documentation and such can be found [here](https://docs.rs/pest/latest/pest/). There's also a digital [book](https://pest.rs/book/) for learning more on `pest` as well.

The current parsing grammar for numbers looks like this:

### Current Parsing Grammar
#### Integers 

```
integer_lit = @{
  "-"? ~ "0x" ~ ASCII_HEX_DIGIT+ |
  "-"? ~ "0o" ~ ASCII_OCT_DIGIT+ |
  "-"? ~ ASCII_DIGIT+ ~ ("KB" | "MB")?
}
```

Breaking this down, the current grammar looks for an integer as such:
1. is it negative or positive: `"-"?`
2. after the sign (or lackthereof), is there a hex or octal identifier: `"0x"` or `"0o"`
3. if so, are the digits in the alphabet for the appropriate set: `ASCII_HEX_DIGIT` or `ASCII_OCT_DIGIT` and are there at least one of them `+`
4. if no octal or hex identifier, is it all ascii digits? `ASCII_DIGIT+`
5. is there a file size notation at the end `("KB" | "MB")?`

#### Floats

```
float_lit = @{
  "-"? ~ ASCII_DIGIT+ ~ DOT ~ ASCII_DIGIT+
}
```

Breaking this down, the current grammar looks for a float as such:
1. is it negative or positive: `"-"?`
2. is there at least one decimal digit: `ASCII_DIGIT+`
3. is there then a dot (.): `DOT`
4. is there then at least one decimal digit again: `ASCII_DIGIT+`

### Proposed Parsing Grammar to Implement Underscores

#### Integers

```
integer_lit = @{
  "-"? ~ "0x" ~ ASCII_HEX_DIGIT+ ~ ("_" | ASCII_HEX_DIGIT)* |
  "-"? ~ "0o" ~ ASCII_OCT_DIGIT+ ~ ("_" | ASCII_OCT_DIGIT)* |
  "-"? ~ ASCII_DIGIT+ ~ ("_" | ASCII_DIGIT)* ~ ("KB" | "MB")?
}
```

Breaking this down, the proposed grammar looks for an integer as such:
1. is it negative or positive: `"-"?`
2. after the sign (or lackthereof), is there a hex or octal identifier: `"0x"` or `"0o"`
3. if so, are the digits in the alphabet for the appropriate set: `ASCII_HEX_DIGIT` or `ASCII_OCT_DIGIT` and are there at least one of them `+`
4. **are there any underscores or digits following the first digit?: `("_" | ASCII_HEX_DIGIT)*` or `("_" | ASCII_OCT_DIGIT)*`**
5. if no octal or hex identifier, is it** at least one ascii digit**? `ASCII_DIGIT+`
6. **if at least one, are there any underscores or digits following the first digit?**: `("_" | ASCII_DIGIT)`
7. is there a file size notation at the end `("KB" | "MB")?`

#### Floats

```
float_lit = @{
  "-"? ~ ASCII_DIGIT+ ~ ("_" | ASCII_DIGIT)* ~ DOT ~ ASCII_DIGIT+ ~ ("_" | ASCII_DIGIT)*
}
```

Breaking this down, the proposed grammar looks for a float as such:
1. is it negative or positive: `"-"?`
2. is there at least one decimal digit: `ASCII_DIGIT+`
3. **if so, is there an underscore or another decimal digit?**: `("_" | ASCII_DIGIT)* `
4. is there then a dot (.): `DOT`
5. is there then at least one decimal digit again: `ASCII_DIGIT+`
6. **if so, is there an underscore or another decimal digit?**: `("_" | ASCII_DIGIT)* `

   
## Checking the Work

I wrote a test rule to ensure the underscores are not included when actually parsing the numbers (decimal numbers, hex numbers, numbers w/ file size, and more!)

```
rule test {
  condition:
    2_000 == 2000 and 100KB == 1_00KB and 0o12 == 1_0 and 0x2_1 == 0x21 and 0x31_1 == 7_8_5
}
```

and it does evaluate to true, indicating YARA-X accurately parses the numbers with and without underscores to the same values. :)

## Finished Work
As with previous days, there's a PR for the work: 
- [#48](https://github.com/VirusTotal/yara-x/pull/48) on YARA-X