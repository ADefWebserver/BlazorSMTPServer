# SMTPServerSvc Program Flow

This diagram illustrates the flow of an SMTP session within the `SMTPServerSvc` project, from connection to message storage or relay.

```mermaid
sequenceDiagram
    participant Client as SMTP Client
    participant Server as SmtpServer (Lib)
    participant Auth as DefaultUserAuthenticator
    participant Filter as DefaultMailboxFilter
    participant Store as DefaultMessageStore
    participant AuthSvc as MailAuthenticationService
    participant DNS as DNS (DnsResolver/LookupClient)
    participant Blob as Azure Blob Storage
    participant Table as Azure Table Storage
    participant RemoteMTA as Remote MTA (Relay)

    Note over Client, Server: Connection Established

    %% Authentication Phase
    Client->>Server: EHLO / AUTH
    Server->>Auth: AuthenticateAsync(user, pass)
    Auth-->>Server: Result (Success/Fail)
    
    alt Authentication Successful
        Server->>Server: Set IsAuthenticated = true
    end

    %% Mail From Phase
    Client->>Server: MAIL FROM: <sender@example.com>
    Server->>Filter: CanAcceptFromAsync(context, sender)
    
    alt Is Authenticated
        Filter-->>Server: Accept
    else Is Unauthenticated
        Filter->>Filter: Check for Spam Test Address
        
        Filter->>DNS: Check Spamhaus (DNSBL)
        DNS-->>Filter: Result
        
        alt Listed in Spamhaus
            Filter->>Table: Log Spam Detection
            Filter->>Filter: Set IsSpam = true
        end

        Filter->>AuthSvc: ValidateSpfAsync(ip, domain)
        AuthSvc->>DNS: Query TXT (SPF)
        DNS-->>AuthSvc: Result
        AuthSvc-->>Filter: Result (Pass/Fail)
        
        alt SPF Fail
            Filter->>Table: Log Spam Detection
            Filter->>Filter: Set IsSpam = true
        end
        
        Filter->>Filter: Store SpfPass & FromDomain in Context
        Filter-->>Server: Accept (even if spam, tagged)
    end

    %% Rcpt To Phase
    Client->>Server: RCPT TO: <recipient@domain.com>
    Server->>Filter: CanDeliverToAsync(context, recipient)
    
    alt Recipient Allowed (Local or Relay if Auth)
        Filter-->>Server: Accept
    else Recipient Not Allowed
        Filter-->>Server: Reject
    end

    %% Data Phase
    Client->>Server: DATA
    Client->>Server: <Message Content>
    Client->>Server: .
    Server->>Store: SaveAsync(context, transaction, buffer)

    Store->>Store: Parse MimeMessage
    Store->>Store: Classify Recipients (Local vs Remote)

    alt Remote Recipients (Relay)
        alt Is Authenticated
            Store->>Store: RelayMessageAsync
            opt DKIM Signing Enabled
                Store->>Store: Sign Message
            end
            Store->>DNS: Lookup MX Records
            Store->>RemoteMTA: Connect & Send (Relay)
        else Not Authenticated
            Store-->>Server: Reject (Auth Required)
        end
    end

    alt Local Recipients (Save)
        Store->>Store: SaveToBlobAsync
        Store->>Store: Check IsSpam flag (from Context)
        
        opt DKIM Check Enabled
            Store->>AuthSvc: ValidateDkimAsync(header)
            AuthSvc->>DNS: Query TXT (DKIM Key)
            AuthSvc-->>Store: Result
        end

        opt DMARC Check Enabled
            Store->>Store: Validate DMARC (SPF Result + DKIM Result)
        end

        Store->>Store: Add X-SMTP-Server-* Headers
        
        opt DKIM Signing Enabled (Local)
            Store->>Store: Sign Message
        end

        alt Is Spam
            Store->>Blob: Upload to "spam" folder
            Store->>Table: Log to "spamlogs"
        else Not Spam
            Store->>Blob: Upload to "recipient" folder
        end
        
        Store->>Blob: Set Blob Metadata
    end

    Store-->>Server: SmtpResponse.Ok
    Server-->>Client: 250 OK
```
