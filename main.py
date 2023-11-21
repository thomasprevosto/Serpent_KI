

# Press the green button in the gutter to run the script.

def print_menu(menu_options) :
    for key in menu_options.keys() :
        print('[',key,']    ',menu_options[key])

def check_choice(choice):
    if choice = '1' :


if __name__ == '__main__':
    menu_options = {
        1: 'Chiffrer/Déchiffrer des messages',
        2: 'Créer un couple de clé publique/privée',
        3: 'Signer un certificat',
        4: 'Vérifier un certificat',
        5: 'Envoyer un message de façon asynchrone',
        6: 'Demander une preuve de connaissance'
        7: 'Quitter'
    }

    while True :
        print_menu(menu_options)
        choice = input("Enter your choice")

        check_()



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
