# `xdvoke` function resolver

```
xdvoke is designed as a drop-in replacement for Golang default "windows" package. 
This is a PoC implementation. `go run .` to run it.
it dynamically resolves the functions by walking the DLL headers.
DLLs are loaded indirectly with RtlQueueWorkItem, waiting a bit, and then calling the legitimate LoadLibrary function.

nothing is new, code heavily inspired (stolen) from WireGuard memmod and rad9800.

Yes, you can yoink the resolver Go assembly stubs from acheron, but why would you want to do assembly for it?
```
# code comparison
```go
// xdvoke
	dll, _ := NewProxyDLL(testMod)
	fmt.Printf("ProxyDLL handle: %x\n", dll.Handle)
	proc, _ := dll.NewProc(testName)
	fmt.Printf("%s -(dyn)> 0x%x\n", testName, proc.Addr())

```
```go
// default windows package
	defdll  := windows.NewLazySystemDLL(testMod)
	fmt.Printf("LazyDLL handle: %x\n", defdll.Handle())
	defproc := defdll.NewProc(testName)
	fmt.Printf("%s -(std)> 0x%x\n", testName, defproc.Addr())
```
