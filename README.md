# Sicherer Passwort-Manager (Python / Tkinter)

Ein eigenständig entwickelter, lokaler Passwort-Manager mit grafischer Benutzeroberfläche, implementiert in Python. Dieses Projekt wurde mit dem Ziel geschaffen, dem Nutzer die **volle Kontrolle über seine sensiblen Zugangsdaten** zu geben, unabhängig von Cloud-Diensten großer Konzerne. Besonderer Fokus lag auf der Implementierung **robuster Sicherheitsmechanismen**, die auf etablierten kryptografischen Verfahren basieren, um Passwörter lokal und sicher zu verwalten.

## Motivation und Zielsetzung

In der heutigen digitalen Landschaft ist die sichere Verwaltung von Passwörtern kritischer denn je. Viele gängige Passwort-Manager sind cloudbasiert, was ein gewisses Vertrauen in Drittanbieter erfordert. Dieses Projekt ist eine Antwort auf den Wunsch nach einer **komplett lokalen, offline-fähigen und hochsicheren Lösung**, die folgende Ziele verfolgt:

* **Maximale Datensicherheit:** Einsatz bewährter kryptografischer Verfahren nach BSI-Empfehlungen.
* **Volle Kontrolle:** Sensible Daten verbleiben lokal auf dem eigenen System.
* **Unabhängigkeit:** Keine Abhängigkeit von externen Servern oder Cloud-Diensten.
* **Lernprojekt:** Vertiefung von Python, GUI-Programmierung (Tkinter) und fortgeschrittener Kryptographie.
* **Benutzerfreundlichkeit:** Intuitive Bedienung trotz hoher Sicherheitsstandards.

## Funktionen

* **Passwort-Generierung:** Konfigurierbare Länge und Zeichentypen (Kleinbuchstaben, Großbuchstaben, Zahlen, Sonderzeichen) für hochkomplexe Passwörter.
* **Passwort-Speicherung:** Sicheres Speichern von Account-Namen, Benutzernamen und Passwörtern.
* **Passwort-Laden:** Übersichtlich listet alle gespeicherten Accounts auf und zeigt bei Auswahl die entschlüsselten Details an.
* **Kopierfunktion:** Einfaches Kopieren von Passwörtern in die Zwischenablage mit automatischer Leerung nach kurzer Zeit aus Sicherheitsgründen.
* **Eintrag-Löschen:** Sicher entfernen von Accounts aus der verschlüsselten Datei.
* **Moderne GUI:** Eine ansprechende grafische Oberfläche dank Tkinter und `ttkthemes`.

## Sicherheitskonzept (BSI-Standards und darüber hinaus)

Die Sicherheit basiert auf einem mehrschichtigen Ansatz, der gängige Best Practices im Kryptographie-Bereich berücksichtigt:

* **Master-Passwort-Ableitung (PBKDF2HMAC):** Das Master-Passwort wird nicht direkt verwendet, sondern dient zur Ableitung eines starken Verschlüsselungsschlüssels mittels PBKDF2HMAC mit SHA256 und 100.000 Iterationen. Dies schützt vor Brute-Force- und Rainbow-Table-Angriffen.
* **Salt-Datei (`salt.key`):** Ein einzigartiger, zufällig generierter Salt wird bei der ersten Nutzung erstellt und separat gespeichert. Er sorgt dafür, dass selbst identische Master-Passwörter zu unterschiedlichen Verschlüsselungsschlüsseln führen.
* **Symmetrische Verschlüsselung (Fernet):** Die eigentlichen Passwortdaten werden mit dem abgeleiteten Schlüssel unter Verwendung des Fernet-Standards verschlüsselt. Fernet basiert auf AES im CBC-Modus mit HMAC-Authentifizierung und gewährleistet Vertraulichkeit und Integrität.
* **Begrenzte Anmeldeversuche:** Die Eingabe des Master-Passworts ist auf wenige Versuche begrenzt, um Brute-Force-Angriffe auf das Master-Passwort zu erschweren.
* **Robuste Fehlerbehandlung:** Um Datenverlust oder unsichere Zustände zu vermeiden, werden Fehler bei ungültigen Passwörtern oder korrupten Dateien abgefangen.

## Installation und Nutzung

### Voraussetzungen

* Python 3 (getestet mit Python 3.9+)
* Die `cryptography` Bibliothek
* Die `ttkthemes` Bibliothek (für den modernen GUI-Look)

Installieren Sie die benötigten Bibliotheken via pip:

```bash
pip install cryptography ttkthemes
