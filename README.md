# Bridge Server

- **Project: Bridge**
- **Doel: Oudere mensen met elkaar verbinden via een eenvoudige chat/social app.**
- **Type: School/MIT project,** ***niet bedoeld voor publieke release.***

Dit is de backend server voor de Bridge-app. Hij regelt gebruikers, profielen, connecties en berichten. De server draait over HTTP op poort 3000.

# Features
- Gebruikers registreren en inloggen met gehashte wachtwoorden (bcrypt)
- Profielen: naam, leeftijd, bio, profielfoto en interesses
- Connecties maken met andere gebruikers
- Berichten versturen en ontvangen tussen connecties
- Eenvoudige feed die random gebruikers laat zien
- HTML-pagina’s voor feed, profiel en chat
- SQLite (Userdata/users.db) voor opslag van alle data
- Optionele debugmodus voor testen (via launch.json)
