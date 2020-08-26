# RSA encryption demo by Elian Felix 08/2020

import RSA_crypto
import random


def int_to_hexstr(number):
    """Takes an integer and returns a hexadecimal bit string representation
    """
    return hex(number)[2:]


def display_hex(number):
    """takes an hexadecimal bit string and outputs it as a formatted block of digits (60 digits per line)
    """

    hexstr = int_to_hexstr(number)
    for i in range(len(hexstr) // 60 + 1):
        if len(hexstr[i*60:]) < 60 or i == len(hexstr) // 60:
            print(hexstr[i*60:], '\n')
        else:
            print(hexstr[i*60:(i+1)*60])


if __name__ == "__main__":
    title = '\nThis RSA asymmetric encryption demo let\'s you choose a level of encryption (in bitsize). \n' \
            'it then computes the setup values, keys, picks some random \"plaintext\" and displays it, \n' \
            'it\'s resulting cipher and the result of decrypting that as well. \n'
    print(title)
    bitsize = int(input('Please enter encryption level (bit length): '))

    kpub, kpr = RSA_crypto.rsa_key_gen(bitsize)

    e, n = kpub
    plaintxt = random.randrange(1, n)
    cipher = RSA_crypto.rsa_encrypt(plaintxt, e, n)
    d = kpr[0]
    cipher_de = RSA_crypto.rsa_decrypt(cipher, d, n)

    # print('\n', kpub, '\n', kpr, '\n')

    print('Our plaintext(in hex): ')
    display_hex(plaintxt)

    print('Is encrypted to(in hex): ')
    display_hex(cipher)

    print('Then decrypted to(in hex): ')
    display_hex(cipher_de)

    print('Is plaintext = decrypted cipher? ', plaintxt == cipher_de)
    if plaintxt == cipher_de:
        print('Job done')
    else:
        print('Oops')
