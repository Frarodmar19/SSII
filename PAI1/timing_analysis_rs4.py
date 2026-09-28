# RS4 - comprobacion de que verificar_firma() es resistente a timing attacks
# Rol C - PAI1 IntegriDos
#
# Idea: si comparas dos strings con == en Python, la comparacion corta en cuanto
# encuentra el primer caracter distinto, entonces el tiempo que tarda depende de
# CUANTOS caracteres coinciden antes del primer fallo. Eso es un timing attack:
# un atacante podria medir tiempos y adivinar la firma byte a byte.
# secrets.compare_digest() evita esto porque siempre compara todo el string
# (tiempo constante, no depende de donde esta el primer fallo).
#
# Este script mide el tiempo real de:
#   1) comparar con == a pelo (mal, vulnerable)
#   2) usar verificar_firma() del proyecto (deberia usar compare_digest por dentro)
# y lo hace para firmas que fallan en distintas posiciones, para ver si el tiempo
# cambia o se mantiene plano.
#
# Ejecutar desde la raiz del repo (donde esta la carpeta app/):
#   python timing_analysis_rs4.py

import time
import statistics
import secrets

from app.security import firmar_mensaje, verificar_firma


def comparacion_mala(a, b):
    # esto es justo lo que NO hay que hacer (vulnerable)
    return a == b


def medir_tiempo(funcion, repeticiones=3000):
    tiempos = []
    for i in range(repeticiones):
        inicio = time.perf_counter_ns()
        funcion()
        fin = time.perf_counter_ns()
        tiempos.append(fin - inicio)
    return statistics.median(tiempos)


session_key = secrets.token_hex(32)
nonce = secrets.token_hex(16)
timestamp = int(time.time())
payload = {
    "sender_iban": "ES9121000418450200051234",
    "receiver_iban": "ES1221000418450200055678",
    "amount": 150.50,
    "concept": "Pago de prueba",
}

firma_buena = firmar_mensaje(session_key, nonce, timestamp, payload)
longitud = len(firma_buena)

# probamos cambiando el primer caracter distinto en distintas posiciones,
# de 8 en 8 para no tardar una eternidad
posiciones = range(0, longitud, 8)

print(f"{'pos byte malo':>15} | {'== a pelo (ns)':>15} | {'verificar_firma (ns)':>22}")

filas = []
for pos in posiciones:
    # generamos una firma que falla justo en esa posicion
    if firma_buena[pos] != "0":
        char_malo = "0"
    else:
        char_malo = "1"
    firma_mala = firma_buena[:pos] + char_malo + firma_buena[pos + 1:]

    t1 = medir_tiempo(lambda: comparacion_mala(firma_buena, firma_mala))
    t2 = medir_tiempo(lambda: verificar_firma(session_key, nonce, timestamp, payload, firma_mala))

    filas.append((pos, t1, t2))
    print(f"{pos:>15} | {t1:>15.0f} | {t2:>22.0f}")

# grafica (si no hay matplotlib no pasa nada, nos quedamos con la tabla)
try:
    import matplotlib.pyplot as plt

    xs = [f[0] for f in filas]
    plt.plot(xs, [f[1] for f in filas], marker="o", label="== (vulnerable)")
    plt.plot(xs, [f[2] for f in filas], marker="o", label="verificar_firma (compare_digest)")
    plt.xlabel("Posicion del primer byte distinto")
    plt.ylabel("Tiempo mediano (ns)")
    plt.title("RS4 - timing attack: == vs compare_digest")
    plt.legend()
    plt.tight_layout()
    plt.savefig("captures/rs4_timing_analysis.png", dpi=150)
    print("\nGrafica guardada en captures/rs4_timing_analysis.png")
except ImportError:
    print("\n(no esta instalado matplotlib, nos quedamos solo con la tabla)")

print("\nLo que se deberia ver: la curva de == sube segun el byte que falla esta")
print("mas lejos (tarda mas en encontrar la diferencia). La curva de verificar_firma")
print("se deberia quedar mas o menos plana, porque compare_digest siempre compara")
print("todo el string independientemente de donde este el fallo.")
