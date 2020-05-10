#include "contexts.hxx"

#include <algorithm>
#include <atomic>
#include <functional>
#include <stdexcept>
#include <unordered_set>

using namespace rstc;

static const std::unordered_set<ZydisRegister> REGISTERS{
    ZYDIS_REGISTER_RAX,    ZYDIS_REGISTER_RCX,        ZYDIS_REGISTER_RDX,
    ZYDIS_REGISTER_RBX,    ZYDIS_REGISTER_RSP,        ZYDIS_REGISTER_RBP,
    ZYDIS_REGISTER_RSI,    ZYDIS_REGISTER_RDI,        ZYDIS_REGISTER_R8,
    ZYDIS_REGISTER_R9,     ZYDIS_REGISTER_R10,        ZYDIS_REGISTER_R11,
    ZYDIS_REGISTER_R12,    ZYDIS_REGISTER_R13,        ZYDIS_REGISTER_R14,
    ZYDIS_REGISTER_R15,    ZYDIS_REGISTER_X87CONTROL, ZYDIS_REGISTER_X87STATUS,
    ZYDIS_REGISTER_X87TAG, ZYDIS_REGISTER_MM0,        ZYDIS_REGISTER_MM1,
    ZYDIS_REGISTER_MM2,    ZYDIS_REGISTER_MM3,        ZYDIS_REGISTER_MM4,
    ZYDIS_REGISTER_MM5,    ZYDIS_REGISTER_MM6,        ZYDIS_REGISTER_MM7,
    ZYDIS_REGISTER_ZMM0,   ZYDIS_REGISTER_ZMM1,       ZYDIS_REGISTER_ZMM2,
    ZYDIS_REGISTER_ZMM3,   ZYDIS_REGISTER_ZMM4,       ZYDIS_REGISTER_ZMM5,
    ZYDIS_REGISTER_ZMM6,   ZYDIS_REGISTER_ZMM7,       ZYDIS_REGISTER_ZMM8,
    ZYDIS_REGISTER_ZMM9,   ZYDIS_REGISTER_ZMM10,      ZYDIS_REGISTER_ZMM11,
    ZYDIS_REGISTER_ZMM12,  ZYDIS_REGISTER_ZMM13,      ZYDIS_REGISTER_ZMM14,
    ZYDIS_REGISTER_ZMM15,  ZYDIS_REGISTER_ZMM16,      ZYDIS_REGISTER_ZMM17,
    ZYDIS_REGISTER_ZMM18,  ZYDIS_REGISTER_ZMM19,      ZYDIS_REGISTER_ZMM20,
    ZYDIS_REGISTER_ZMM21,  ZYDIS_REGISTER_ZMM22,      ZYDIS_REGISTER_ZMM23,
    ZYDIS_REGISTER_ZMM24,  ZYDIS_REGISTER_ZMM25,      ZYDIS_REGISTER_ZMM26,
    ZYDIS_REGISTER_ZMM27,  ZYDIS_REGISTER_ZMM28,      ZYDIS_REGISTER_ZMM29,
    ZYDIS_REGISTER_ZMM30,  ZYDIS_REGISTER_ZMM31,      ZYDIS_REGISTER_RFLAGS,
};

static const std::unordered_map<ZydisRegister, ZydisRegister>
    REGISTER_PROMOTION_MAP{
        { ZYDIS_REGISTER_AL, ZYDIS_REGISTER_RAX },
        { ZYDIS_REGISTER_AH, ZYDIS_REGISTER_RAX },
        { ZYDIS_REGISTER_BL, ZYDIS_REGISTER_RBX },
        { ZYDIS_REGISTER_BH, ZYDIS_REGISTER_RBX },
        { ZYDIS_REGISTER_CL, ZYDIS_REGISTER_RCX },
        { ZYDIS_REGISTER_CH, ZYDIS_REGISTER_RCX },
        { ZYDIS_REGISTER_DL, ZYDIS_REGISTER_RDX },
        { ZYDIS_REGISTER_DH, ZYDIS_REGISTER_RDX },
        { ZYDIS_REGISTER_SPL, ZYDIS_REGISTER_RSP },
        { ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_RBP },
        { ZYDIS_REGISTER_SIL, ZYDIS_REGISTER_RSI },
        { ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_RDI },
        { ZYDIS_REGISTER_R8B, ZYDIS_REGISTER_R8 },
        { ZYDIS_REGISTER_R9B, ZYDIS_REGISTER_R9 },
        { ZYDIS_REGISTER_R10B, ZYDIS_REGISTER_R10 },
        { ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R11 },
        { ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R12 },
        { ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R13 },
        { ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R14 },
        { ZYDIS_REGISTER_R15B, ZYDIS_REGISTER_R15 },
        { ZYDIS_REGISTER_AX, ZYDIS_REGISTER_RAX },
        { ZYDIS_REGISTER_CX, ZYDIS_REGISTER_RCX },
        { ZYDIS_REGISTER_DX, ZYDIS_REGISTER_RDX },
        { ZYDIS_REGISTER_BX, ZYDIS_REGISTER_RBX },
        { ZYDIS_REGISTER_SP, ZYDIS_REGISTER_RSP },
        { ZYDIS_REGISTER_BP, ZYDIS_REGISTER_RBP },
        { ZYDIS_REGISTER_SI, ZYDIS_REGISTER_RSI },
        { ZYDIS_REGISTER_DI, ZYDIS_REGISTER_RDI },
        { ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R8 },
        { ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_R9 },
        { ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R10 },
        { ZYDIS_REGISTER_R11W, ZYDIS_REGISTER_R11 },
        { ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R12 },
        { ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R13 },
        { ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R14 },
        { ZYDIS_REGISTER_R15W, ZYDIS_REGISTER_R15 },
        { ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_RAX },
        { ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_RCX },
        { ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_RDX },
        { ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_RBX },
        { ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_RSP },
        { ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_RBP },
        { ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_RSI },
        { ZYDIS_REGISTER_EDI, ZYDIS_REGISTER_RDI },
        { ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R8 },
        { ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R9 },
        { ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R10 },
        { ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_R11 },
        { ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R12 },
        { ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R13 },
        { ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R14 },
        { ZYDIS_REGISTER_R15D, ZYDIS_REGISTER_R15 },
        { ZYDIS_REGISTER_ST0, ZYDIS_REGISTER_MM0 },
        { ZYDIS_REGISTER_ST1, ZYDIS_REGISTER_MM1 },
        { ZYDIS_REGISTER_ST2, ZYDIS_REGISTER_MM2 },
        { ZYDIS_REGISTER_ST3, ZYDIS_REGISTER_MM3 },
        { ZYDIS_REGISTER_ST4, ZYDIS_REGISTER_MM4 },
        { ZYDIS_REGISTER_ST5, ZYDIS_REGISTER_MM5 },
        { ZYDIS_REGISTER_ST6, ZYDIS_REGISTER_MM6 },
        { ZYDIS_REGISTER_ST7, ZYDIS_REGISTER_MM7 },
        { ZYDIS_REGISTER_XMM0, ZYDIS_REGISTER_ZMM0 },
        { ZYDIS_REGISTER_XMM1, ZYDIS_REGISTER_ZMM1 },
        { ZYDIS_REGISTER_XMM2, ZYDIS_REGISTER_ZMM2 },
        { ZYDIS_REGISTER_XMM3, ZYDIS_REGISTER_ZMM3 },
        { ZYDIS_REGISTER_XMM4, ZYDIS_REGISTER_ZMM4 },
        { ZYDIS_REGISTER_XMM5, ZYDIS_REGISTER_ZMM5 },
        { ZYDIS_REGISTER_XMM6, ZYDIS_REGISTER_ZMM6 },
        { ZYDIS_REGISTER_XMM7, ZYDIS_REGISTER_ZMM7 },
        { ZYDIS_REGISTER_XMM8, ZYDIS_REGISTER_ZMM8 },
        { ZYDIS_REGISTER_XMM9, ZYDIS_REGISTER_ZMM9 },
        { ZYDIS_REGISTER_XMM10, ZYDIS_REGISTER_ZMM10 },
        { ZYDIS_REGISTER_XMM11, ZYDIS_REGISTER_ZMM11 },
        { ZYDIS_REGISTER_XMM12, ZYDIS_REGISTER_ZMM12 },
        { ZYDIS_REGISTER_XMM13, ZYDIS_REGISTER_ZMM13 },
        { ZYDIS_REGISTER_XMM14, ZYDIS_REGISTER_ZMM14 },
        { ZYDIS_REGISTER_XMM15, ZYDIS_REGISTER_ZMM15 },
        { ZYDIS_REGISTER_XMM16, ZYDIS_REGISTER_ZMM16 },
        { ZYDIS_REGISTER_XMM17, ZYDIS_REGISTER_ZMM17 },
        { ZYDIS_REGISTER_XMM18, ZYDIS_REGISTER_ZMM18 },
        { ZYDIS_REGISTER_XMM19, ZYDIS_REGISTER_ZMM19 },
        { ZYDIS_REGISTER_XMM20, ZYDIS_REGISTER_ZMM20 },
        { ZYDIS_REGISTER_XMM21, ZYDIS_REGISTER_ZMM21 },
        { ZYDIS_REGISTER_XMM22, ZYDIS_REGISTER_ZMM22 },
        { ZYDIS_REGISTER_XMM23, ZYDIS_REGISTER_ZMM23 },
        { ZYDIS_REGISTER_XMM24, ZYDIS_REGISTER_ZMM24 },
        { ZYDIS_REGISTER_XMM25, ZYDIS_REGISTER_ZMM25 },
        { ZYDIS_REGISTER_XMM26, ZYDIS_REGISTER_ZMM26 },
        { ZYDIS_REGISTER_XMM27, ZYDIS_REGISTER_ZMM27 },
        { ZYDIS_REGISTER_XMM28, ZYDIS_REGISTER_ZMM28 },
        { ZYDIS_REGISTER_XMM29, ZYDIS_REGISTER_ZMM29 },
        { ZYDIS_REGISTER_XMM30, ZYDIS_REGISTER_ZMM30 },
        { ZYDIS_REGISTER_XMM31, ZYDIS_REGISTER_ZMM31 },
        { ZYDIS_REGISTER_YMM0, ZYDIS_REGISTER_ZMM0 },
        { ZYDIS_REGISTER_YMM1, ZYDIS_REGISTER_ZMM1 },
        { ZYDIS_REGISTER_YMM2, ZYDIS_REGISTER_ZMM2 },
        { ZYDIS_REGISTER_YMM3, ZYDIS_REGISTER_ZMM3 },
        { ZYDIS_REGISTER_YMM4, ZYDIS_REGISTER_ZMM4 },
        { ZYDIS_REGISTER_YMM5, ZYDIS_REGISTER_ZMM5 },
        { ZYDIS_REGISTER_YMM6, ZYDIS_REGISTER_ZMM6 },
        { ZYDIS_REGISTER_YMM7, ZYDIS_REGISTER_ZMM7 },
        { ZYDIS_REGISTER_YMM8, ZYDIS_REGISTER_ZMM8 },
        { ZYDIS_REGISTER_YMM9, ZYDIS_REGISTER_ZMM9 },
        { ZYDIS_REGISTER_YMM10, ZYDIS_REGISTER_ZMM10 },
        { ZYDIS_REGISTER_YMM11, ZYDIS_REGISTER_ZMM11 },
        { ZYDIS_REGISTER_YMM12, ZYDIS_REGISTER_ZMM12 },
        { ZYDIS_REGISTER_YMM13, ZYDIS_REGISTER_ZMM13 },
        { ZYDIS_REGISTER_YMM14, ZYDIS_REGISTER_ZMM14 },
        { ZYDIS_REGISTER_YMM15, ZYDIS_REGISTER_ZMM15 },
        { ZYDIS_REGISTER_YMM16, ZYDIS_REGISTER_ZMM16 },
        { ZYDIS_REGISTER_YMM17, ZYDIS_REGISTER_ZMM17 },
        { ZYDIS_REGISTER_YMM18, ZYDIS_REGISTER_ZMM18 },
        { ZYDIS_REGISTER_YMM19, ZYDIS_REGISTER_ZMM19 },
        { ZYDIS_REGISTER_YMM20, ZYDIS_REGISTER_ZMM20 },
        { ZYDIS_REGISTER_YMM21, ZYDIS_REGISTER_ZMM21 },
        { ZYDIS_REGISTER_YMM22, ZYDIS_REGISTER_ZMM22 },
        { ZYDIS_REGISTER_YMM23, ZYDIS_REGISTER_ZMM23 },
        { ZYDIS_REGISTER_YMM24, ZYDIS_REGISTER_ZMM24 },
        { ZYDIS_REGISTER_YMM25, ZYDIS_REGISTER_ZMM25 },
        { ZYDIS_REGISTER_YMM26, ZYDIS_REGISTER_ZMM26 },
        { ZYDIS_REGISTER_YMM27, ZYDIS_REGISTER_ZMM27 },
        { ZYDIS_REGISTER_YMM28, ZYDIS_REGISTER_ZMM28 },
        { ZYDIS_REGISTER_YMM29, ZYDIS_REGISTER_ZMM29 },
        { ZYDIS_REGISTER_YMM30, ZYDIS_REGISTER_ZMM30 },
        { ZYDIS_REGISTER_YMM31, ZYDIS_REGISTER_ZMM31 },
    };

static std::atomic<size_t> GLOBAL_ID = 0;

template<class T>
inline void hash_combine(std::size_t &seed, const T &v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
}

Context::Context(Address source)
    : parent_(nullptr)
    , hash_(0)
    , id_(++GLOBAL_ID)
    , caller_id_(0)
    , registers_()
    , memory_(source)
    , flatten_(true)
{
    set_all_registers_zero(source);
}

Context::Context(Context const *parent, ParentRole parent_role)
    : parent_(parent)
    , hash_(parent->hash_)
    , id_(++GLOBAL_ID)
    , caller_id_(parent_role == ParentRole::Caller ? parent->id_ :
                                                     parent->caller_id_)
    , registers_()
    , memory_(parent->memory_.get_root_source())
    , flatten_(false)
{
    if (parent_role != ParentRole::Default) {
        this->flatten();
    }
}

std::optional<Context::ValueSource> Context::get(ZydisRegister reg) const
{
    Context const *c = this;
    if (auto it = REGISTER_PROMOTION_MAP.find(reg);
        it != REGISTER_PROMOTION_MAP.end()) {
        reg = it->second;
    }
    else if (!REGISTERS.contains(reg)) {
        return std::nullopt;
    }
    do {
        if (auto it = c->registers_.find(reg); it != c->registers_.end()) {
            return it->second;
        }
        if (c->flatten_) {
            break;
        }
        c = c->parent_;
    } while (c);
    return std::nullopt;
}

VirtualMemory::Sources Context::get(uintptr_t address, size_t size) const
{
    if (!flatten_) {
        throw std::runtime_error(
            "Context::get for memory works only with flattened Context");
    }
    return memory_.get(address, size);
}

void Context::set(ZydisRegister reg, Address source, Value value)
{
    set(reg, ValueSource{ value, source });
}

void Context::set(ZydisRegister reg, ValueSource valsrc)
{
    if (auto it = REGISTER_PROMOTION_MAP.find(reg);
        it != REGISTER_PROMOTION_MAP.end()) {
        reg = it->second;
    }
    else if (!REGISTERS.contains(reg)) {
        return;
    }
    if (auto old = get(reg); old) {
        hash_combine(hash_, old->source);
        if (old->value) {
            hash_combine(hash_, *old->value);
        }
        // Don't "un"-hash `reg`,
        // as we will hash it only if old value didn't exist
    }
    else {
        hash_combine(hash_, reg);
    }
    if (valsrc.value) {
        hash_combine(hash_, *valsrc.value);
    }
    hash_combine(hash_, valsrc.source);
    registers_.insert_or_assign(reg, valsrc);
}

void Context::set_all_registers_zero(Address source)
{
    for (auto reg : REGISTERS) {
        set(reg, source, 0);
    }
}

void Context::set(uintptr_t address, size_t size, Address source)
{
    memory_.assign(address, size, source);
}

void Context::flatten()
{
    if (flatten_) {
        return;
    }
    for (auto reg : REGISTERS) {
        if (auto valsrc = get(reg); valsrc) {
#ifndef NDEBUG
            set(reg, *valsrc);
#else
            // Set without changing hash_
            registers_.insert_or_assign(reg, *valsrc);
#endif
        }
    }
    std::vector<Context const *> context_path;
    context_path.push_back(parent_);
    while (true) {
        if (auto base_context = context_path.back();
            !base_context->flatten_ && base_context->parent_) {
            context_path.push_back(base_context->parent_);
        }
        else {
            break;
        }
    }
    for (auto it = context_path.rbegin(); it != context_path.rend(); ++it) {
        for (auto const &m : (*it)->memory_.get_all()) {
            set(m.start, m.end - m.start, m.source);
        }
    }
    assert(hash_ == parent_->hash_);
    parent_ = nullptr;
    flatten_ = true;
}

Context Context::make_child(ParentRole parent_role) const
{
    return Context(this, parent_role);
}
