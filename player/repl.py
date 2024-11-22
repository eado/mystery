import socket

from security import *  # Assuming all functions are defined in security.py

# Function map to store the outputs
results = {}

def print_usage(function_name):
    """Print the usage for each function"""
    usage_guide = {
        'load_private_key': 'Usage: load_private_key <filename>',
        'load_peer_public_key': 'Usage: load_peer_public_key <peer_key>',
        'load_ca_public_key': 'Usage: load_ca_public_key <filename>',
        'load_certificate': 'Usage: load_certificate <filename>',
        'generate_private_key': 'Usage: generate_private_key',
        'derive_public_key': 'Usage: derive_public_key',
        'derive_secret': 'Usage: derive_secret',
        'derive_keys': 'Usage: derive_keys',
        'sign': 'Usage: sign <data>',
        'verify': 'Usage: verify <data> <signature> <authority>',
        'generate_nonce': 'Usage: generate_nonce <size>',
        'encrypt_data': 'Usage: encrypt_data <data>',
        'decrypt_cipher': 'Usage: decrypt_cipher <cipher> <iv>',
        'get_certificate': 'Usage: get_certificate',
        'get_public_key': 'Usage: get_public_key'
    }

    if function_name in usage_guide:
        print(usage_guide[function_name])
    else:
        print("Unknown function")


def print_variable(index):
    """Print the value of the variable stored in results"""
    if index in results:
        value = results[index]
        if isinstance(value, bytes):
            print(f"${index}: {value}")
        else:
            print(f"${index}: {value}")
    else:
        print(f"Error: ${index} not found")


def print_help(tokens):
    """Print the help information for all commands"""

    if len(tokens) > 1:
        print_usage(tokens[1])
        return

    help_text = """
    Get the offset (in bytes) of a stored buffer: e.g. $0+3

    Available Commands:
    load_private_key <filename>      - Load private key from file
    load_peer_public_key <peer_key>  - Load peer public key from buffer
    load_ca_public_key <filename>    - Load CA public key from file
    load_certificate <filename>      - Load certificate from file
    generate_private_key             - Generate a private key
    derive_public_key                - Derive public key from private key
    derive_secret                    - Derive shared secret using private and peer keys
    derive_keys                      - Derive ENC and MAC keys using HKDF
    sign <data>                      - Sign a buffer using private key
    verify <data> <signature> <authority> - Verify a signature using a given authority
    generate_nonce <size>            - Generate cryptographically secure random data
    encrypt_data <data>              - Encrypt data using derived shared secret
    decrypt_cipher <cipher> <iv>     - Decrypt data using derived shared secret
    get_certificate                  - Retrieve the loaded certificate
    get_public_key                   - Retrieve the derived public key
    print <variable>                 - Print the value of a stored buffer (e.g., $0, $1, ...)
    recv                             - Get data from server
    send <variable>                  - Send buffer to server
    help                             - Show this help information
    help <function>                  - Show usage for a function
    ec_ca_public_key                 - Use this as input to `verify` as a given authority
    ec_peer_public_key               - Use this as input to `verify` as a given authority
    ec_priv_key                      - Use this as input to `verify` as a given authority
    """
    print(help_text)


def repl():
    """REPL loop for functions"""

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(('roundtrip', 8080))

    print("INTERNAL NETSIFT TOOLCHAIN")
    while True:
        try:
            # Prompt for user input
            user_input = input("> ").strip()
            if not user_input:
                continue

            # Parse the user input
            tokens = user_input.split()
            command = tokens[0]

            if command == "exit":
                break

            elif command == "help":
                print_help(tokens)
                continue

            elif command == "print":  # Print command for variables
                if len(tokens) != 2:
                    print("Usage: print <variable>")
                    continue
                try:
                    index = int(tokens[1][1:])  # Get index from $n
                    print_variable(index)
                except ValueError:
                    print("Error: Invalid variable reference")
                continue

            elif command == "recv":
                packet = c.recv(2000)
                if len(packet) > 0:
                    results[len(results)] = packet
                    print_variable(len(results) - 1)
                continue

            elif command == "send":
                try:
                    index = int(tokens[1][1:])
                    if index in results:
                        c.send(results[index])
                    else:
                        print(f"Error: ${index} not found")
                        break
                except ValueError:
                    c.send(bytes(tokens[1], encoding="utf8"))
                    continue

            elif command in globals():  # Check if the function exists
                func = globals()[command]

                # If argument refers to a previous result, substitute $n with the result
                args = []
                for token in tokens[1:]:
                    if token.startswith('$'):
                        try:
                            index = int(token[1:])
                            if index in results:
                                args.append(results[index])
                            else:
                                print(f"Error: $ {index} not found")
                                break
                        except ValueError:
                            print(f"Error: Invalid result reference {token}")
                            break
                    else:
                        args.append(token)

                # Execute function based on argument types
                if len(args) == 0:  # Functions with no arguments
                    result = func()
                elif len(args) == 1:  # Functions with one argument
                    if command in ['load_peer_public_key', 'sign', 'encrypt_data']:
                        if not isinstance(args[0], bytes):
                            args[0] = bytes(args[0], encoding='utf8')
                    if command == "generate_nonce":
                        args[0] = int(args[0])
                    result = func(args[0])
                elif len(args) == 2:  # Functions with two arguments
                    result = func(args[0], args[1])
                elif len(args) == 3:
                    if not isinstance(args[0], bytes):
                        args[0] = bytes(args[0], encoding='utf8')
                    if args[2] == 'ec_peer_public_key':
                        args[2] = ec_peer_public_key
                    elif args[2] == 'ec_ca_public_key':
                        args[2] = ec_ca_public_key
                    elif args[2] == 'ec_priv_key':
                        args[2] = ec_priv_key
                    result = func(args[0], args[1], args[2])
                else:
                    print_usage(command)
                    continue

                # Only add to results if the function returns something
                if result is not None:
                    if command == "encrypt_data":
                        iv, ciphertext = result
                        iv_index = len(results)
                        ciphertext_index = len(results) + 1
                        results[iv_index] = iv
                        results[ciphertext_index] = ciphertext
                        print(f"IV: ${iv_index}: ${iv.hex()}")
                        print(
                            f"Ciphertext: ${ciphertext_index}: ${ciphertext.hex()}")
                    else:
                        results[len(results)] = result
                        print_variable(len(results) - 1)
            else:
                print_usage(command)

        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    try:
        repl()
    except KeyboardInterrupt:
        exit()
