#!/usr/bin/python
# The same token intentionally appears on two separate lines, so that we can verify
# that both occurrences are reported (and labelled) independently.
TOKEN_ONE = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'
# An unrelated line, so the two occurrences don't sit next to each other.
TOKEN_TWO = 'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5'


def main():
    print('Hello world!')


if __name__ == '__main__':
    main()
