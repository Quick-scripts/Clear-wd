# Clear-wd
Clears the current working directory. Avoids fatal typos.

## How to use
Execute `clearwd` in the shell and it will remove all files, directories, and subdirectories. It additionally takes path arguments, clearing all files in the specified path.

## Examples
`clearwd` would remove all files and directories recursively in the `./` directory

`clearwd foo bar` would clear directories `foo` and `bar`

## Installation
`clearwd` can be moved to path in `/usr/local/bin/` with `mv clearwd /use/local/bin` 
