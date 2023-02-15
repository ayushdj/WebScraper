# Project 2: Web Scraper

Ayush Dhananjai & Matt Faucher

### High Level Approach

The following details our high level approach with this project:

1. Make a GET request to obtain the latest session ID's, cookies and CSRF tokens from the browser.
2. Make a POST request with each user's correct credentials such that we can 
   log in to the website.
3. Make another GET request to obtain the HTML for the page after we log in such that
    we can begin our algorithm
4. Run a Breadth-first-Search by first parsing the HTML for the current page.
5. Visit all the tags with a class called "secret_flag", looking for the flags.
    Repeat this algorithm on all pages (i.e. friends etc.) and then stop
   the algorithm when we get to 5 secret flags.
   
### Challenges Faced

The main challenge we faced was with making the GET and POST requests. We faced many string
formatting issues which resulted in getting multiple 400 errors (i.e. bad requests). To fix this, we updated the
sessionID's in our login function to keep the connection alive. Once we figured out how to keep
the connection alive, the rest of the process became quite trivial (i.e. implementing the parsing code
and the BFS).

### How did we test the code
We tested the code in two main phases:
Phase 1: make sure that we can establish a proper connection to the correct URL's (i.e. look for 200 responses)
Phase 2: make sure that we get the flags
Phase 3: optimize our code such that we can get the flags in a reasonable time (i.e. less than 10 minutes)

### Who contributed to what

Ayush contributions:

- client.py
    -  lines 4 - 44
- socket_connection.py
    - lines 23 - 51
    - lines 76 - 92  
    - lines 94 - 128
    - lines 141 - 154
    
131 lines 

Matt's Contributions:

- html_parse.py
    - lines 3 - 50
- socket_connection.py
    - lines 1 - 21
    - lines 53-61
    - lines 63 - 74
    - lines 94 - 128
    - lines 130 - 139
    - lines 156 - 172

145 lines


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


