# Project 2: Web Scraper

Ayush Dhananjai & Matt Faucher

### Files

1. Requests
  - File to handle making and receiving web requests through a web socket.

2. HTML
  - File to handle parsing required elements and building lists of links to visit out of HTML.
  
3. Graph Traversal (?)
  - Potentially use the other tools from Requests & HTML files to traverse the website's links and finding secret flags.

4. CLI
  - File to handle CLI arg parsing and running the application.

### Secret Flag Identification

Secret flags may be hidden on any page on Fakebook, and their relative location
on each page may be different.

Each secret flag is a 64 character long sequences of random alphanumerics.

All secret flags will appear in the following format (which makes them easy to identify):

```html
<h2 class='secret_flag' style="color:red">FLAG: 64-characters-of-random-alphanumerics</h2>
```

### Running the Application

Usage goes as follows:

```bash
./webcrawler [username] [password]
```
