from Scripts import Menu_interactions as menu

# Press the green button in the gutter to run the script.

#Test Commit
def print_menu(options) :
    for key in options.keys() :
        print('[',key,']    ',options[key])
    return input("Enter your choice :   ")
if __name__ == '__main__':
    options = {
        1: 'Encrypt/Decrypt a message',
        2: 'Create a pair of Public/Private keys (Generate a big prime number)',
        3: 'Sign a certificate',
        4: 'Verify a certificate',
        5: 'Send a message asynchronously',
        6: 'Ask for a knowledge proof',
        7: 'Exit'
    }

    while True :
        choice = print_menu(options)
        menu.check_choice(choice)



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
