from argparse import ArgumentParser


def read(filename):
    pass


def main():
    parser = ArgumentParser()
    parser.add_argument('filename')
    args = parser.parse_args()
    read(args.filename)


if __name__ == '__main__':
    main()
