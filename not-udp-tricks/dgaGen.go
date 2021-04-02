package main

import (
	"os"
    "fmt"
    "time"
    "strings"
    "strconv"
    "math/rand"
    "encoding/hex"
    "encoding/base64"
)

func init () {
	rand.Seed(time.Now().UnixNano())
}

func randInt(min int, max int) int {
    return min + rand.Intn(max-min)
}

func genLatin (domainLength int) string {
	year := randInt(1, 100000)
	month := randInt(1, 100000)
	day := randInt(1, 100000)
	domain := ""

	for i := 0; i < domainLength; i++ {
		year = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
		month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8)
		day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
		domain += string(((year ^ month ^ day) % 25) + 97)
	}

	return domain
}

func genNumbers (domainLength int) string {
	domain := ""

	for i := 0; i < domainLength; i++ {
		domain += strconv.Itoa(randInt(0, 10))
	}

	return domain
}

func genHex (domainLength int) string {
	return hex.EncodeToString([]byte(genLatin(domainLength)))
}

func genBase64 (domainLength int) string {
	return strings.ToLower(base64.StdEncoding.EncodeToString([]byte(genLatin(domainLength))))
}

func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: dgaGen	file_to_write	how_much_records_do_you_want_for_each_aloritm\n\nExample: dgaGen dataset.txt 5000")
		return
	}

	file, err := os.OpenFile(os.Args[1], os.O_RDWR|os.O_CREATE, 0755)
	
	howMuchRecordsEach, err := strconv.Atoi(os.Args[2])
	
	if err != nil {
		fmt.Println(err)
	}


	for i := 0; i <= howMuchRecordsEach; i++ {
	    // fmt.Print("\033[H\033[2J")

	    // fmt.Println(genLatin(17))
	    // fmt.Println(genNumbers(17))
	    // fmt.Println(genHex(9))
	    // fmt.Println(genBase64(12))

	    file.WriteString(genLatin(17) + ", 1\n")
	    file.WriteString(genNumbers(17) + ", 1\n")
	    file.WriteString(genHex(9) + ", 1\n")
	    file.WriteString(genBase64(12) + ", 1\n")
	    
	    fmt.Println(i)
	}
}
