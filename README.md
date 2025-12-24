# BLAZOR SMTP SERVER
## Read the Blog post: [Create Your Own SMTP Server Using Aspire 13](https://blazorhelpwebsite.com/ViewBlogPost/20080)
## Also see: [https://github.com/ADefWebserver/BlazorSMTPForwarder](https://github.com/ADefWebserver/BlazorSMTPForwarder)
<img width="945" height="705" alt="image" src="https://github.com/user-attachments/assets/e34394b3-ae06-4e1e-b94f-7222e63a4e94" />

<img width="1176" height="698" alt="image" src="https://github.com/user-attachments/assets/ecb0d8fe-16fa-4529-b80d-1308fb674187" />

<img width="923" height="835" alt="image" src="https://github.com/user-attachments/assets/0a1d97c1-95f0-4bb4-8b22-1cff40503e6c" />

<img width="917" height="718" alt="image" src="https://github.com/user-attachments/assets/091eac31-038a-49a9-9dd0-944083b60075" />

<img width="946" height="593" alt="image" src="https://github.com/user-attachments/assets/06c4c482-e0ec-44ab-9ac6-08bc0d7d0001" />

<img width="812" height="641" alt="image" src="https://github.com/user-attachments/assets/b9bf32ed-a711-4838-853e-bec6b94786e2" />

<img width="601" height="411" alt="image" src="https://github.com/user-attachments/assets/a00e8f9e-1c5e-4799-bd00-59341d1e96c5" />

<img width="715" height="287" alt="image" src="https://github.com/user-attachments/assets/587ab70b-ef1e-47b2-af31-ac6970f187e7" />

# SMTPServerSvc Program Flow

This diagram illustrates the flow of an SMTP session within the `SMTPServerSvc` project, from connection to message storage.

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
Also see: [https://github.com/ADefWebserver/BlazorSMTPForwarder](https://github.com/ADefWebserver/BlazorSMTPForwarder)
