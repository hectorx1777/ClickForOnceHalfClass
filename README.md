# ClickForOnceHalfClass
A Half Evasive Class for Clickonce Payloads

## Complementary Code to the BlogPost 
[(https://ndolecki.gitlab.io/posts/clickonce)](https://ndolecki.gitlab.io/posts/clickonce)

## Usage 
- Copy the class within a Hijackable .net DLL and compile it . 
- Embed the shellcode you like using the Csharp Script included within this repo.
- Recreate the Hash values for .net Execution as Described in the blogpost or other sources.
- Host your modified .application file and try it out. 

## This class was used to play around with legit Hijackablae CLickonce Payloads with a little bit of EDR evasion

## Techniques
| Category | Techniques |
|----------|------------|
| **Injection** | Thread context hijack (default), QueueUserAPC, CreateRemoteThread |
| **Staging** | Suspended sacrificial process, VirtualAllocEx + WriteProcessMemory (RWX) |
| **Evasion** | PEB walk, API hashing, dynamic delegates, XOR’d embedded payload |

## End-to-end sequence

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'background': 'transparent',
    'primaryColor': '#000000',
    'primaryBorderColor': '#444444',
    'primaryTextColor': '#ffffff',
    'secondaryColor': '#000000',
    'secondaryBorderColor': '#444444',
    'secondaryTextColor': '#ffffff',
    'tertiaryColor': '#000000',
    'tertiaryTextColor': '#ffffff',
    'actorBkg': '#000000',
    'actorBorder': '#666666',
    'actorTextColor': '#ffffff',
    'actorLineColor': '#8ec5ff',
    'signalColor': '#8ec5ff',
    'signalTextColor': '#e8f0ff',
    'lineColor': '#8ec5ff',
    'textColor': '#e8f0ff',
    'labelBoxBkgColor': '#000000',
    'labelBoxBorderColor': '#666666',
    'labelTextColor': '#e8f0ff'
  }
}}%%
sequenceDiagram
    participant M as Main2Test
    participant R as Manifest resource
    participant H as NativeFromHashes
    participant P as wmiprvse.exe (suspended)

    M->>R: Read encrypted .bin
    M->>M: popoInPlace (XOR decrypt)
    M->>H: CreateProcessA (suspended)
    H->>P: Primary thread created suspended
    M->>H: VirtualAllocEx + WriteProcessMemory
    H->>P: Shellcode in remote memory
    M->>H: GetThreadContext
    M->>M: Set RIP/EIP = shellcode
    M->>H: SetThreadContext + ResumeThread
    P->>P: Thread runs shellcode
```



# EDR Detection Results

|EDR Vendor |Result |Status |
|------------|--------|--------|
| Cortex | Not detected | 🟢 |
| CrowdStrike | Not detected (after bloating) | 🟢 |
| Bitdefender | Detected - malicious sacrificial process | 🔴 |
| MDE (Microsoft Defender for Endpoint) | Initial access not detected; beacon caught after memory scan | 🟡 |
| SentinelOne | Not detected | 🟢 |

**Legend:** 🟢 Not detected · 🔴 Detected · 🟡 Partial / delayed detection

