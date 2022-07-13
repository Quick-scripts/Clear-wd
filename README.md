# Clear-wd
Clears the current working directory. Avoids fatal typos.

## How to use
Execute `clearwd` in the shell and it will remove all files, directories, and subdirectories. It additionally takes path arguments, clearing all files in the specified path.

## Examples
`clearwd` would remove all files and directories recursively in the `./` directory

`clearwd foo bar` would clear directories `foo` and `bar`

## Installation
First enter the repository with `cd Clear-wd`

In order to build the script from the provided `main.sh`, you must run `build.sh`. `build.sh` requires the `shc` compiler which is available.

Otherwise, you may simply build the C code with any C compiler using `./cbuild.sh <compiler name>` where `<compiler name>` is the name of the compiler.

To add `clearwd` to path, you may move `clearwd` to local binaries with `mv ./clearwd $HOME/.local/bin`
