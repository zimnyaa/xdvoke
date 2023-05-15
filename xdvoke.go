package main
import (
	"syscall"
	"time"
	"golang.org/x/sys/windows"
	"fmt"
	"unsafe"
)



type ProxyDLLError struct {
	Err     error
	ObjName string
	Msg     string
}

type ProxyDLL struct {
	Name   string
	Handle windows.Handle
}

type DProc struct {
	Dll  *ProxyDLL
	Name string
	addr uintptr
}

func (p *DProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	switch len(a) {
	case 0:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), 0, 0, 0)
	case 1:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], 0, 0)
	case 2:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], 0)
	case 3:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], a[2])
	case 4:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], 0, 0)
	case 5:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], 0)
	case 6:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5])
	case 7:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], 0, 0)
	case 8:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0)
	case 9:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 10:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], 0, 0)
	case 11:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], 0)
	case 12:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 13:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], 0, 0)
	case 14:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], 0)
	case 15:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	default:
		panic("Call " + p.Name + " with too many arguments " + itoa(len(a)) + ".")
	}
}


func (p *DProc) Addr() uintptr {
	return p.addr
}

func NewProxyDLL(name string) (dll *ProxyDLL, err error) {
	if name == "kernel32.dll" || name == "ntdll.dll" {
		rdll, _ := windows.LoadDLL(name)
		d := &ProxyDLL{
			Name:   name,
			Handle: rdll.Handle,
		}
		return d, nil
	}
	namep, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	modntdll, _          := NewProxyDLL("ntdll.dll")
	modkernel32, _       := NewProxyDLL("kernel32.dll")
	fRtlQueueWorkItem, _ := modntdll.NewProc("RtlQueueWorkItem")
	fLoadLibraryW, _     := modkernel32.NewProc("LoadLibraryW")


	syscall.Syscall(fRtlQueueWorkItem.Addr(), 3, uintptr(fLoadLibraryW.Addr()), uintptr(unsafe.Pointer(namep)), uintptr(0))


	time.Sleep(500 * time.Millisecond)

	rdll, e := windows.LoadDLL(name)

	if e != nil {
		return nil, fmt.Errorf("Failed to load")
	}
	d := &ProxyDLL{
		Name:   name,
		Handle: rdll.Handle,
	}
	return d, nil
}

func (dll *ProxyDLL) NewProc(name string) (*DProc, error) {

	dosHeader := (*IMAGE_DOS_HEADER)(a2p(uintptr(dll.Handle)))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return nil, fmt.Errorf("Not an MS-DOS binary (provided: %x, expected: %x)", dosHeader.E_magic, IMAGE_DOS_SIGNATURE)
	}


	oldHeader := (*IMAGE_NT_HEADERS)(a2p(uintptr(dll.Handle) + uintptr(dosHeader.E_lfanew)))
	if oldHeader.Signature != IMAGE_NT_SIGNATURE {
		return nil, fmt.Errorf("Not an NT binary (provided: %x, expected: %x)", oldHeader.Signature, IMAGE_NT_SIGNATURE)
	}

	directory := oldHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if directory.Size == 0 {
		return nil, fmt.Errorf("No export table found")
	}


	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(oldHeader.OptionalHeader.ImageBase + uintptr(directory.VirtualAddress)))
	if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
		return nil, fmt.Errorf("No functions exported")
	}
	if exports.NumberOfNames == 0 {
		return nil, fmt.Errorf("No functions exported by name")
	}

	var nameRefs []uint32
	unsafeSlice(unsafe.Pointer(&nameRefs), a2p(oldHeader.OptionalHeader.ImageBase+uintptr(exports.AddressOfNames)), int(exports.NumberOfNames))
	var ordinals []uint16
	unsafeSlice(unsafe.Pointer(&ordinals), a2p(oldHeader.OptionalHeader.ImageBase+uintptr(exports.AddressOfNameOrdinals)), int(exports.NumberOfNames))
	for i := range nameRefs {
		nameArray := windows.BytePtrToString((*byte)(a2p(oldHeader.OptionalHeader.ImageBase + uintptr(nameRefs[i]))))
		if nameArray == name {
			nameord := ordinals[i]
			funcaddr := oldHeader.OptionalHeader.ImageBase + uintptr(*(*uint32)(a2p(oldHeader.OptionalHeader.ImageBase + uintptr(exports.AddressOfFunctions) + uintptr(nameord)*4)))
			return &DProc{dll, name, funcaddr}, nil
		}
	}
	return nil, fmt.Errorf("Function not found")
}

func main() {
	testName := "AmsiScanBuffer"
	testMod := "amsi.dll"


	dll, _ := NewProxyDLL(testMod)
	fmt.Printf("ProxyDLL handle: %x\n", dll.Handle)
	proc, _ := dll.NewProc(testName)
	fmt.Printf("%s -(dyn)> 0x%x\n", testName, proc.Addr())

	defdll  := windows.NewLazySystemDLL(testMod)
	fmt.Printf("LazyDLL handle: %x\n", defdll.Handle())
	defproc := defdll.NewProc(testName)
	fmt.Printf("%s -(std)> 0x%x\n", testName, defproc.Addr())
	

	fmt.Printf("%v diff\n", int(defproc.Addr() - proc.Addr()))
	for {}
}


