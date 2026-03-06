/*
 * stripped-app.c - mixed text and numeric processing utility.
 *
 * Designed to stress-test DetectFunctionsFromELF with a variety of
 * function shapes: large loops, small leaves, multi-caller functions,
 * recursive functions, and functions with complex control flow.
 * No anti-inlining attributes: gcc -O2 is free to do what it wants.
 */

#include <stdio.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* String analysis                                                      */
/* ------------------------------------------------------------------ */

/* Count whitespace-delimited words. */
int word_count(const char *s)
{
    int n = 0, in_word = 0;
    for (; *s; s++) {
        if (isspace((unsigned char)*s)) {
            in_word = 0;
        } else if (!in_word) {
            in_word = 1;
            n++;
        }
    }
    return n;
}

/* Return the character length of the longest word. */
int longest_word(const char *s)
{
    int max = 0, cur = 0;
    for (; *s; s++) {
        if (isspace((unsigned char)*s)) {
            if (cur > max)
                max = cur;
            cur = 0;
        } else {
            cur++;
        }
    }
    return cur > max ? cur : max;
}

/* Count vowels (case-insensitive). */
int vowel_count(const char *s)
{
    int n = 0;
    for (; *s; s++) {
        switch (tolower((unsigned char)*s)) {
        case 'a': case 'e': case 'i': case 'o': case 'u':
            n++;
        }
    }
    return n;
}

/* Count occurrences of character c. */
int char_count(const char *s, char c)
{
    int n = 0;
    for (; *s; s++)
        if (*s == c)
            n++;
    return n;
}

/* Return 1 if every character in s is ASCII printable, 0 otherwise. */
int is_printable(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e)
            return 0;
    return 1;
}

/* djb2 hash over the string bytes. */
unsigned long checksum(const char *s)
{
    unsigned long h = 5381;
    for (; *s; s++)
        h = h * 33 + (unsigned char)*s;
    return h;
}

/* ------------------------------------------------------------------ */
/* Integer array processing                                             */
/* ------------------------------------------------------------------ */

/* Return the minimum value in arr[0..n-1]. */
int arr_min(const int *arr, int n)
{
    int m = arr[0];
    for (int i = 1; i < n; i++)
        if (arr[i] < m)
            m = arr[i];
    return m;
}

/* Return the maximum value in arr[0..n-1]. */
int arr_max(const int *arr, int n)
{
    int m = arr[0];
    for (int i = 1; i < n; i++)
        if (arr[i] > m)
            m = arr[i];
    return m;
}

/* Return the sum of arr[0..n-1]. */
long arr_sum(const int *arr, int n)
{
    long s = 0;
    for (int i = 0; i < n; i++)
        s += arr[i];
    return s;
}

/* In-place insertion sort. */
void arr_sort(int *arr, int n)
{
    for (int i = 1; i < n; i++) {
        int key = arr[i], j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/* Return the index of val in arr[0..n-1], or -1 if not found. */
int arr_find(const int *arr, int n, int val)
{
    for (int i = 0; i < n; i++)
        if (arr[i] == val)
            return i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Recursive functions                                                  */
/* ------------------------------------------------------------------ */

/* Return the n-th Fibonacci number (doubly recursive). */
int fib(int n)
{
    if (n <= 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}

/* Return the GCD of a and b (recursive Euclidean algorithm). */
int gcd(int a, int b)
{
    return b == 0 ? a : gcd(b, a % b);
}

/* ------------------------------------------------------------------ */
/* Reporting                                                            */
/* ------------------------------------------------------------------ */

/* Print string metrics: called from main with several inputs. */
void report_str(const char *label, const char *s)
{
    printf("%s: words=%d longest=%d vowels=%d spaces=%d printable=%d csum=%lu\n",
           label,
           word_count(s),
           longest_word(s),
           vowel_count(s),
           char_count(s, ' '),
           is_printable(s),
           checksum(s));
}

/* Print array metrics: called from main with several arrays. */
void report_arr(const char *label, int *arr, int n)
{
    arr_sort(arr, n);
    printf("%s: min=%d max=%d sum=%ld fib7=%d gcd=%d find3=%d\n",
           label,
           arr_min(arr, n),
           arr_max(arr, n),
           arr_sum(arr, n),
           fib(7),
           gcd(arr_min(arr, n), arr_max(arr, n)),
           arr_find(arr, n, 3));
}

int main(void)
{
    report_str("s1", "the quick brown fox jumps over the lazy dog");
    report_str("s2", "pack my box with five dozen liquor jugs");
    report_str("s3", "how vexingly quick daft zebras jump");

    int a[] = {5, 2, 8, 1, 9, 3, 7, 4, 6};
    int b[] = {12, 3, 7, 15, 1, 8};
    report_arr("a", a, 9);
    report_arr("b", b, 6);
    return 0;
}
