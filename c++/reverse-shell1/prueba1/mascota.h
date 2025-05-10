#pragma once

class Mascota {
public:
    Mascota(const char* nombre, const char* servidor, int puerto);
private:
    void conectarServidor();
    const char* nombre;
    const char* servidor;
    int puerto;
};
