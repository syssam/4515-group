package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
)

var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// generateRandomPassword generates a random password
func generateRandomPassword(length int) string {
	var password strings.Builder
	for i := 0; i < length; i++ {
		randomIndex := rand.Intn(len(charset))
		password.WriteByte(charset[randomIndex])
	}
	return password.String()
}

// generatePassword generates a password based on index
func generatePassword(index int, length int) string {
	var password strings.Builder
	base := len(charset)
	for i := 0; i < length; i++ {
		password.WriteByte(charset[index%base])
		index /= base
	}
	return password.String()
}

// bruteForceCrackPassword tries to crack the password using brute force
func bruteForceCrackPassword(ctx context.Context, target string, length int, startIndex int, endIndex int, ch chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := startIndex; i <= endIndex; i++ {
		select {
		case <-ctx.Done():
			return // Stop if context is canceled
		default:
			password := generatePassword(i, length)
			if password == target {
				ch <- password
				return
			}
		}
	}
}

// measureCrackTime measures time to crack a password
func measureCrackTime(length int) (string, time.Duration) {
	targetPassword := generateRandomPassword(length)
	fmt.Printf("Generated target password: %s\n", targetPassword)

	workerCount := 1000
	var wg sync.WaitGroup
	ch := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()
	totalCombinations := int(math.Pow(float64(len(charset)), float64(length)))
	rangeSize := totalCombinations / workerCount

	for i := 0; i < workerCount; i++ {
		startIndex := i * rangeSize
		endIndex := startIndex + rangeSize - 1
		if i == workerCount-1 {
			endIndex = totalCombinations - 1
		}
		wg.Add(1)
		go func(start, end int) {
			bruteForceCrackPassword(ctx, targetPassword, length, start, end, ch, &wg)
		}(startIndex, endIndex)
	}

	var foundPassword string
	select {
	case foundPassword = <-ch:
		cancel() // Cancel all other goroutines
	case <-time.After(time.Hour * 1): // Timeout if needed
		foundPassword = "Not found"
		fmt.Println("Password not found")
	}
	wg.Wait()

	duration := time.Since(startTime)
	return foundPassword, duration
}

func main() {
	passwordLengths := []int{1, 2, 3, 4, 5, 6}
	durations := make([]opts.LineData, 0)
	repeats := 10

	for _, length := range passwordLengths {
		var totalDuration time.Duration
		for i := 0; i < repeats; i++ {
			fmt.Printf("Attempting to crack password of length %d (Attempt %d)...\n", length, i+1)
			_, duration := measureCrackTime(length)
			totalDuration += duration
		}
		averageDuration := totalDuration / time.Duration(repeats)
		durations = append(durations, opts.LineData{Value: averageDuration.Seconds()})
		fmt.Printf("Average time to crack password of length %d: %v\n", length, averageDuration)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderChart(w, r, passwordLengths, durations)
	})
	http.ListenAndServe(":8081", nil)
	fmt.Printf("Server started at http://localhost:8081\n")
}

func renderChart(w http.ResponseWriter, _ *http.Request, passwordLengths []int, durations []opts.LineData) {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{Theme: types.ThemeWesteros}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Password Crack Time",
			Subtitle: "Logarithmic scale",
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Type: "log",
		}),
	)

	t := true
	line.SetXAxis(passwordLengths).
		AddSeries("Time (s)", durations, charts.WithLabelOpts(opts.Label{Show: &t})).
		SetSeriesOptions(charts.WithLineChartOpts(opts.LineChart{Smooth: &t}))
	line.Render(w)
}
