<div align="left" style="position: relative;">

<h1>Authentication token module for Golang</h1>

<p align="left">
  <img src="https://img.shields.io/github/license/fsobh/token?style=plastic&logo=opensourceinitiative&logoColor=white&color=2691fb" alt="license">
  <img src="https://img.shields.io/badge/Coverage-57.7%25-2691fb?style=plastic&logo=none&logoColor=white&labelColor=555555&borderRadius=10" alt="coverage">
  <img src="https://img.shields.io/github/last-commit/fsobh/token?style=plastic&logo=git&logoColor=white&color=2691fb" alt="last-commit">
  <img src="https://img.shields.io/github/languages/top/fsobh/token?style=plastic&color=2691fb" alt="repo-top-language">
  <img src="https://img.shields.io/github/languages/count/fsobh/token?style=plastic&color=2691fb" alt="repo-language-count">
</p>
<p align="left">Built with the tools and technologies:</p>
<p align="left">
  <img src="https://img.shields.io/badge/Go-00ADD8.svg?style=plastic&logo=Go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/GitHub%20Actions-2088FF.svg?style=plastic&logo=GitHub-Actions&logoColor=white" alt="GitHub%20Actions">
</p>
</div>
<br clear="right">

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [📁 Project Structure](#-project-structure)
    - [📂 Project Index](#-project-index)
- [🚀 Getting Started](#-getting-started)
    - [☑️ Prerequisites](#-prerequisites)
    - [⚙️ Installation](#-installation)
    - [🤖 Usage](#-usage)
    - [🧪 Testing](#-testing)
- [📌 Project Roadmap](#-project-roadmap)
- [🔰 Contributing](#-contributing)
- [🎗 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)

---

## 📍 Overview

**A Go module for seamless JWT & PASETO token integration**

---

## 👾 Features

- **JWT**
- **PASETO V2**
- **PASETO V3**
---

## 📁 Project Structure

```sh
└── token/
    ├── .github
    │   └── workflows
    │       └── test-and-coverage.yml
    ├── LICENSE.txt
    ├── README.MD
    ├── coverage.svg
    ├── go.mod
    ├── go.sum
    ├── jwt_asym_maker.go
    ├── jwt_asym_maker_test.go
    ├── jwt_maker.go
    ├── jwt_maker_test.go
    ├── main
    │   ├── demo
    │   │   ├── util.go
    │   │   ├── v2.go
    │   │   └── v3.go
    │   └── test.go
    ├── makefile
    ├── maker.go
    ├── paseto_v2_local_maker.go
    ├── paseto_v2_local_maker_test.go
    ├── paseto_v2_public_maker.go
    ├── paseto_v2_public_maker_test.go
    ├── paseto_v3_local_maker.go
    ├── paseto_v3_local_maker_test.go
    ├── paseto_v3_public_maker.go
    ├── paseto_v3_public_maker_test.go
    ├── payload.go
    ├── payload_test.go
    └── testCoverage.out
```


### 📂 Project Index
<details open>
  <summary><b><code>token/</code></b></summary>
  <details> <!-- __root__ Submodule -->
    <summary><b>__root__</b></summary>
    <blockquote>
      <table>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/LICENSE.txt'>LICENSE.txt</a></b></td>
        <td><code>❯ License file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/jwt_maker.go'>jwt_maker.go</a></b></td>
        <td><code>❯ Token maker for Symmetric JWT tokens</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/maker.go'>maker.go</a></b></td>
        <td><code>❯ Token maker interface</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v3_local_maker_test.go'>paseto_v3_local_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/jwt_asym_maker_test.go'>jwt_asym_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/makefile'>makefile</a></b></td>
        <td><code>❯ make file for tests</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v2_public_maker.go'>paseto_v2_public_maker.go</a></b></td>
        <td><code>❯ Token maker for Paseto V2 Public tokens (Asymmetrical)</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/go.mod'>go.mod</a></b></td>
        <td><code>❯ go mod file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/jwt_maker_test.go'>jwt_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/go.sum'>go.sum</a></b></td>
        <td><code>❯ go sum</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v2_public_maker_test.go'>paseto_v2_public_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v2_local_maker.go'>paseto_v2_local_maker.go</a></b></td>
        <td><code>❯ Token maker for Paseto V2 Local tokens (Symmetrical)</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v3_local_maker.go'>paseto_v3_local_maker.go</a></b></td>
        <td><code>❯ Token maker for Paseto V3 Local tokens (Symmetrical)</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/payload.go'>payload.go</a></b></td>
        <td><code>❯ Predefined payload with username and token id fields </code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/testCoverage.out'>testCoverage.out</a></b></td>
        <td><code>❯ Test coverage results</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/jwt_asym_maker.go'>jwt_asym_maker.go</a></b></td>
        <td><code>❯ Token maker for Asymmetric JWT tokens</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/payload_test.go'>payload_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v2_local_maker_test.go'>paseto_v2_local_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v3_public_maker_test.go'>paseto_v3_public_maker_test.go</a></b></td>
        <td><code>❯ Test file</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/paseto_v3_public_maker.go'>paseto_v3_public_maker.go</a></b></td>
        <td><code>❯ Token maker for Paseto V3 Public tokens (Asymmetrical)</code></td>
      </tr>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/README.MD'>README.MD</a></b></td>
        <td><code>❯ Documentation</code></td>
      </tr>
      </table>
    </blockquote>
  </details>
  <details> <!-- .github Submodule -->
    <summary><b>.github</b></summary>
    <blockquote>
      <details>
        <summary><b>workflows</b></summary>
        <blockquote>
          <table>
          <tr>
            <td><b><a href='https://github.com/fsobh/token/blob/master/.github/workflows/test-and-coverage.yml'>test-and-coverage.yml</a></b></td>
            <td><code>❯ Work flow to run unit tests (on push) and update readme with test coverage badge</code></td>
          </tr>
          </table>
        </blockquote>
      </details>
    </blockquote>
  </details>
  <details> <!-- main Submodule -->
    <summary><b>main</b></summary>
    <blockquote>
      <table>
      <tr>
        <td><b><a href='https://github.com/fsobh/token/blob/master/main/test.go'>test.go</a></b></td>
        <td><code>❯ Playground file for development</code></td>
      </tr>
      </table>
      <details>
        <summary><b>demo</b></summary>
        <blockquote>
          <table>
          <tr>
            <td><b><a href='https://github.com/fsobh/token/blob/master/main/demo/util.go'>util.go</a></b></td>
            <td><code>❯ Playground file for development</code></td>
          </tr>
          <tr>
            <td><b><a href='https://github.com/fsobh/token/blob/master/main/demo/v3.go'>v3.go</a></b></td>
            <td><code>❯ Playground file for development</code></td>
          </tr>
          <tr>
            <td><b><a href='https://github.com/fsobh/token/blob/master/main/demo/v2.go'>v2.go</a></b></td>
            <td><code>❯ Playground file for development</code></td>
          </tr>
          </table>
        </blockquote>
      </details>
    </blockquote>
  </details>
</details>

---
## 🚀 Getting Started

### ☑️ Prerequisites

Before getting started with token, ensure your runtime environment meets the following requirements:

- **Programming Language:** Go
- **Package Manager:** Go modules


### ⚙️ Installation


**Install the project dependencies:**


**Using `go modules`** &nbsp; [<img align="center" src="https://img.shields.io/badge/Go-00ADD8.svg?style={badge_style}&logo=go&logoColor=white" />](https://golang.org/)

```sh
❯ go get github.com/fsobh/token
```




### 🤖 Usage

- **Paseto V2**
```go
package main

import (
	"aidanwoods.dev/go-paseto"
	"encoding/json"
	"fmt"
	"github.com/fsobh/token"
	"log"

	"time"
)

func toJSON(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal to JSON: %v", err)
	}
	return string(jsonBytes)
}

func main() {

	// ** Paseto V2 Local **

	// Generate Keys
	symmetricKeyV2 := paseto.NewV2SymmetricKey()

	// convert keys to Hex
	symmetricKeyStringV2 := symmetricKeyV2.ExportHex()

	localMakerV2, err := token.NewPasetoV2Local(symmetricKeyStringV2)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V2 local token maker: %w", err)
	}

	localTokenStringV2, localPayloadV2, err := localMakerV2.CreateToken("alice", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V2 local token: %w", err)
	}

	fmt.Println("Created Paseto V2 local Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      localTokenStringV2,
		"payload":    localPayloadV2,
		"expiration": localPayloadV2.ExpiredAt,
	}))

	// Verify the token
	verifiedPayload, err := localMakerV2.VerifyToken(localTokenStringV2)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V2 local token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Paseto V2 local Payload (JSON):")
	fmt.Println(toJSON(verifiedPayload))




	// ** Paseto V2 Public **

	// generate keys
	privateKeyV2 := paseto.NewV2AsymmetricSecretKey()
	publicKeyV2 := privateKeyV2.Public()

	// convert keys to Hex
	privateKeyStringV2 := privateKeyV2.ExportHex()
	publicKeyStringV2 := publicKeyV2.ExportHex()

	publicMakerV2, err := token.NewPasetoV2Public(privateKeyStringV2, publicKeyStringV2)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V2 public token maker: %w", err)
	}


	publicTokenStringV2, publicPayloadV2, err := publicMakerV2.CreateToken("charlie", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V2 public token: %w", err)
	}


	fmt.Println("Created Paseto V2 public Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      publicTokenStringV2,
		"payload":    publicPayloadV2,
		"expiration": publicPayloadV2.ExpiredAt,
	}))


	publicVerifiedPayloadV2, err := publicMakerV2.VerifyToken(publicTokenStringV2)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V2 public token: %w", err)
	}


	fmt.Println("Verified Paseto V2 public Payload (JSON):")
	fmt.Println(toJSON(publicVerifiedPayloadV2))

}
```
- **Paseto V3**
```go
package main

import (
	"aidanwoods.dev/go-paseto"
	"encoding/json"
	"fmt"
	"github.com/fsobh/token"
	"log"

	"time"
)

func toJSON(data interface{}) string {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal to JSON: %v", err)
	}
	return string(jsonBytes)
}

func main() {
	
	// ** Paseto V3 Local **

	symmetricKeyV3 := paseto.NewV3SymmetricKey()
	symmetricKeyStringV3 := symmetricKeyV3.ExportHex()
	
	localMakerV3, err := token.NewPasetoV3Local(symmetricKeyStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 local token maker: %w", err)
	}

	localTokenStringV3, localPayloadV3, err := localMakerV3.CreateToken("bob", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 local token: %w", err)
	}

	fmt.Println("Created Paseto V3 local Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      localTokenStringV3,
		"payload":    localPayloadV3,
		"expiration": localPayloadV3.ExpiredAt,
	}))

	localVerifiedPayloadV3, err := localMakerV3.VerifyToken(localTokenStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V3 local token: %w", err)
	}

	fmt.Println("Verified Paseto V3 local Payload (JSON):")
	fmt.Println(toJSON(localVerifiedPayloadV3))

	
	
	
	
	// ** Paseto V3 Public **

	privateKeyV3 := paseto.NewV3AsymmetricSecretKey()
	publicKeyV3 := privateKeyV3.Public()

	privateKeyStringV3 := privateKeyV3.ExportHex()
	publicKeyStringV3 := publicKeyV3.ExportHex()
	
	publicMakerV3, err := token.NewPasetoV3Public(privateKeyStringV3, publicKeyStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 public token maker: %w", err)
	}

	// Create a token
	publicTokenStringV3, publicPayloadV3, err := publicMakerV3.CreateToken("dave", 24*time.Hour)
	if err != nil {
		_ = fmt.Errorf("failed to create Paseto V3 public token: %w", err)
	}

	// Display token and payload in JSON
	fmt.Println("Created Paseto V3 public Token (JSON):")
	fmt.Println(toJSON(map[string]interface{}{
		"token":      publicTokenStringV3,
		"payload":    publicPayloadV3,
		"expiration": publicPayloadV3.ExpiredAt,
	}))

	// Verify the token
	publicVerifiedPayloadV3, err := publicMakerV3.VerifyToken(publicTokenStringV3)
	if err != nil {
		_ = fmt.Errorf("failed to verify Paseto V3 public token: %w", err)
	}

	// Display verified payload in JSON
	fmt.Println("Verified Paseto V3 public Payload (JSON):")
	fmt.Println(toJSON(publicVerifiedPayloadV3))
}
```


### 🧪 Testing
Run the test suite using the following command:
**Using `go modules`** &nbsp; [<img align="center" src="https://img.shields.io/badge/Go-00ADD8.svg?style={badge_style}&logo=go&logoColor=white" />](https://golang.org/)

```sh
❯ make test
```


---
## 📌 Project Roadmap

- [X] **`Task 1`**: <strike>Implement JWT options.</strike>
- [X] **`Task 2`**: <strike>Implement Paseto V2-V3 public and local options</strike>
- [ ] **`Task 3`**: Implement feature Paseto V4 public and local options.

---

## 🔰 Contributing

- **💬 [Join the Discussions](https://github.com/fsobh/token/discussions)**: Share your insights, provide feedback, or ask questions.
- **🐛 [Report Issues](https://github.com/fsobh/token/issues)**: Submit bugs found or log feature requests for the `token` project.
- **💡 [Submit Pull Requests](https://github.com/fsobh/token/blob/main/CONTRIBUTING.md)**: Review open PRs, and submit your own PRs.

<details closed>
<summary>Contributing Guidelines</summary>

1. **Fork the Repository**: Start by forking the project repository to your github account.
2. **Clone Locally**: Clone the forked repository to your local machine using a git client.
   ```sh
   git clone https://github.com/fsobh/token
   ```
3. **Create a New Branch**: Always work on a new branch, giving it a descriptive name.
   ```sh
   git checkout -b new-feature-x
   ```
4. **Make Your Changes**: Develop and test your changes locally.
5. **Commit Your Changes**: Commit with a clear message describing your updates.
   ```sh
   git commit -m 'Implemented new feature x.'
   ```
6. **Push to github**: Push the changes to your forked repository.
   ```sh
   git push origin new-feature-x
   ```
7. **Submit a Pull Request**: Create a PR against the original project repository. Clearly describe the changes and their motivations.
8. **Review**: Once your PR is reviewed and approved, it will be merged into the main branch. Congratulations on your contribution!
</details>

<details closed>
<summary>Contributor Graph</summary>
<br>
<p align="left">
   <a href="https://github.com{/fsobh/token/}graphs/contributors">
      <img src="https://contrib.rocks/image?repo=fsobh/token">
   </a>
</p>
</details>

---

## 🎗 License

This project is protected under the [MIT](https://choosealicense.com/licenses/mit/) License. For more details, refer to the [LICENSE](./LICENSE.txt) file.

---

## 🙌 Acknowledgments

- [aidantwoods](https://github.com/aidantwoods) for implementing [go-paseto](https://github.com/aidantwoods/go-paseto) for the core functionality

---