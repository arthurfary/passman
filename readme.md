# Passman, the Tool-Agnostic; Local-First password manager

## What is Passman?

Passman is a password (pass) manager (man) that focuses on giving the user control over its own passwords.

## The Passman Philosophy.

Passman follows a very simple philosophy: **Your passwords, your problem**. By that is understood to the user that they are responsible for their passwords. Any security can only be as secure as its weakest link, passman aims to put that weakest link directly in the hands of the user.

## Local-First

 your precious info to a third party, with Passman all of your passwords are encrypted and saved locally, each on their own separate **password file**. (also referred to as 'passman files')

With this approach, the user can be sure that their passwords are not only securely encrypted, but also securely stored, backed-up and up-to-date. Their passwords are as secure as they want to.

## Tool-Agnostic

One of the core philosophies of passman is tool agnosticism

# How to use Passman

Download the [latest Passman release](https://github.com/arthurfary/passman/releases) and save it wherever you like.

# To use Passman, simply call the executable from a command line.

## Create a new password
- To create a new random password use:
```
passman new
```
You will be prompted to insert a master password and a service name

- You can also pass arguments directly:
```
passman new google
```
> Create a password for a Google account, file will be saved as 'google'.

**Passman saves passwords locally**
- Windows: `C:\Users\USER\Documents\Passwords\`
- Linux: `~/.passwords/`
# Get a password
- To get a password use:
```
passman get
```
- You can also pass arguments directly:
```
passman get google
```
## Register a password (Save an already existing password into Passman file)
> Be sure to ONLY register secure passwords, remember, you are the weakest link
- To register a password use:
```
passman register
```
- You can also pass arguments directly:
```
passman register github MYVERYSECUREPASSWORD
```

## You can also list all password files with `passman list`

## Running:
For development, run it with cargo using `cargo run ARGS`, you may need to give permissions to the project folder, the simplest way is by doing `chmod +x .` while on the correct directory.
