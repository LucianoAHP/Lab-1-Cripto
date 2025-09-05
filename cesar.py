def cesar(texto: str, corrimiento: int) -> str:
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    n = len(alfabeto)

    resultado = ""
    for char in texto:
        if char in alfabeto:
            indice = alfabeto.index(char)
            nuevo_indice = (indice + corrimiento) % n
            resultado += alfabeto[nuevo_indice]
        else:
            resultado += char

    return resultado


# Ejemplo de uso
if __name__ == "__main__":
    texto = "Hola MundoZz"
    corrimiento = 5
    cifrado = cesar(texto, corrimiento)
    print("Texto original:", texto)
    print("Texto cifrado :", cifrado)
