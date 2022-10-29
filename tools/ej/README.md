EJ (short for “Easy Journal”) is the document system that MaraDNS
uses; this is in response to my translators asking for a single unified
document format which can be converted in to the following three formats:

* HTML documents (albeit with minimal styling)
* Man pages
* Plain text documents

The EJ tools were originally written in Perl in 2002.  In 2022, the
tools were re-written in Lua 5.1 so that building MaraDNS’s documents
no longer need a non-POSIX tool which isn’t included with MaraDNS.

# Getting the EJ tools to work

The EJ tools are Lua scripts, written for Lua 5.1.  Should the scripts
not run, make sure to have either Lua 5.1 (a standard package for 
man *NIX distributions) or Lunacy (see below) installed.

MaraDNS includes a full fork of Lua5.1 called `lunacy`, to compile it,
enter the `coLunacyDNS/lunacy` directory, use `make` to compile `lunacy`,
then, as root `cp lunacy /usr/local/bin`.

# Using EJ

EJ is an XML-like format (without a DTD, alas) which has the following 
tags.

Comments:

Comments begin with `<!--` and end with `-->`; these comments are removed
before an ej document is translated.  

Tags to put in the header of the document:

HEAD: Marks the beginning of the header; terminated by /HEAD

TH: Placed in the HEAD of the document; this is the arguments to give TH 
when translated to a man page; terminated by /TH; only applies when 
converting ej documents to *ROFF man pages

DTWIDTH: How wide to make DT entries when translating to the man page
         format

TITLE: The title of the document when the document is translated to HTML

BODYFLAGS: Flags given to the BODY tag when this document is translated
           to HTML

meta HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8": Mandatory;
all documents must be encoded as utf-8 documents.

Tags to put in the body of the document:

BODY: Marks the beginning of the body; terminated by /BODY

H1: Same as in HTML; becomes .SH when translated in to a man page; placed 
in BODY of message; terminated by /H1

H2: Heading level 2; becomes a fairly complex series of roff code when
    translated to man page format

B: Bold text; terminated by /B

I: Italic text; terminated by /I

UL: Start a bulleted list; terminated by /UL

LI: Bulleted list item.  Please minimize tag use in bulleted lists,
    using only B and I tags.

OL: Rendered as a bulleted list with ej2txt.  Should not be used
    with ej2man.

PRE: Unformatted text follows; this tag is terminated by /PRE
     Note that HTML tags are shown as is in PRE blocks; unlike HTML,
     tags have no meta-significance in a PRE block but are instead 
     shown as the raw tag.  Likewise, < and > can be in PRE blocks.

INCLUDE "filename": Embed the listed filename as the next section of the doc

BLOCKQUOTE: Move the following text over; terminated by /BLOCKQUOTE

P: Indicates a new paragraph

A: Indicates an anchor; same as a HTML anchor; terminated with /A

TT: Indicates fix-point text (only rendered in HTML pages)

TABLE: Signifies the beginning of a basic three-column table; terminated
       with /TABLE

TD: Signifies the start of a single table cell

TR: Signifies the start of a new row with the table

BR: Line break

DL: Start a definition list

DT: Start to describe the item to define; can be closed by /DT
    (to work around a bug in the Konqueror web browser)

DD: Start to define the item just declared with the DL tag; can be closed
    by /DD 

HR: This is used to split up sections of the document

HIBIT: This was a special tag used to indicate a section that needs
       hi-bit (non-ASCII Unicode) characters.  Now that UTF-8 is universal,
       this tag is no longer used.

NOFMT: This is a special tag used to indicate to not attempt to make
       lines under 72 columns wide when generating text and *ROFF 
       documents.  This should be placed in the head of documents if
       the language is not a Latin/Greek/Cyrillic lanaguage (i.e. a
       language where a given UTF-8 code point does not have a fixed
       width).  This tag must be placed in the head section of the
       document.

