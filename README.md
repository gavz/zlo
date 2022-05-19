# zlo
A utility for detecting and patching AV/EDR hooks.

<div align="center">
    <img src="https://user-images.githubusercontent.com/105472509/169201270-3aadd577-6e67-419d-8c55-79352ea2b281.png" width="500px"><br>
</div>

## Description
`zlo` Is an AV/EDR hooking detection utility that attempts to detect userland hooks by dumping functions from several DLLs and checking the opcodes.

### Features
- Patches hooks (if found)
- Detects and reports hooks (if found)

### Built with
- C++

## Getting started
### Compiling
To compile `zlo`, simply execute the following script:
- `build.bat` (Make sure you have the MinGW Compiler installed and you have set the PATH variable!)

### Usage
- `zlo.exe`

## Credits
```
https://github.com/xmmword
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
