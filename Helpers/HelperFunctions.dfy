module HelperFunctions {
  // to convert string to array of chars, taken from wilcoxjay on GitHub
  method ArrayFromSeq<A>(s: seq<A>) returns (a: array<A>)
    ensures a[..] == s
  {
    a := new A[|s|] ( i requires 0 <= i < |s| => s[i] );
  }
}