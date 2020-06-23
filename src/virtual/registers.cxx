#include "registers.hxx"

using namespace rstc;
using namespace rstc::virt;

const std::unordered_map<ZydisRegister, Registers::Reg> Registers::register_map{
    { ZYDIS_REGISTER_RAX, Registers::RAX },
    { ZYDIS_REGISTER_RCX, Registers::RCX },
    { ZYDIS_REGISTER_RDX, Registers::RDX },
    { ZYDIS_REGISTER_RBX, Registers::RBX },
    { ZYDIS_REGISTER_RSP, Registers::RSP },
    { ZYDIS_REGISTER_RBP, Registers::RBP },
    { ZYDIS_REGISTER_RSI, Registers::RSI },
    { ZYDIS_REGISTER_RDI, Registers::RDI },
    { ZYDIS_REGISTER_R8, Registers::R8 },
    { ZYDIS_REGISTER_R9, Registers::R9 },
    { ZYDIS_REGISTER_R10, Registers::R10 },
    { ZYDIS_REGISTER_R11, Registers::R11 },
    { ZYDIS_REGISTER_R12, Registers::R12 },
    { ZYDIS_REGISTER_R13, Registers::R13 },
    { ZYDIS_REGISTER_R14, Registers::R14 },
    { ZYDIS_REGISTER_R15, Registers::R15 },
    { ZYDIS_REGISTER_X87CONTROL, Registers::X87CONTROL },
    { ZYDIS_REGISTER_X87STATUS, Registers::X87STATUS },
    { ZYDIS_REGISTER_X87TAG, Registers::X87TAG },
    { ZYDIS_REGISTER_MM0, Registers::MM0 },
    { ZYDIS_REGISTER_MM1, Registers::MM1 },
    { ZYDIS_REGISTER_MM2, Registers::MM2 },
    { ZYDIS_REGISTER_MM3, Registers::MM3 },
    { ZYDIS_REGISTER_MM4, Registers::MM4 },
    { ZYDIS_REGISTER_MM5, Registers::MM5 },
    { ZYDIS_REGISTER_MM6, Registers::MM6 },
    { ZYDIS_REGISTER_MM7, Registers::MM7 },
    { ZYDIS_REGISTER_ZMM0, Registers::ZMM0 },
    { ZYDIS_REGISTER_ZMM1, Registers::ZMM1 },
    { ZYDIS_REGISTER_ZMM2, Registers::ZMM2 },
    { ZYDIS_REGISTER_ZMM3, Registers::ZMM3 },
    { ZYDIS_REGISTER_ZMM4, Registers::ZMM4 },
    { ZYDIS_REGISTER_ZMM5, Registers::ZMM5 },
    { ZYDIS_REGISTER_ZMM6, Registers::ZMM6 },
    { ZYDIS_REGISTER_ZMM7, Registers::ZMM7 },
    { ZYDIS_REGISTER_ZMM8, Registers::ZMM8 },
    { ZYDIS_REGISTER_ZMM9, Registers::ZMM9 },
    { ZYDIS_REGISTER_ZMM10, Registers::ZMM10 },
    { ZYDIS_REGISTER_ZMM11, Registers::ZMM11 },
    { ZYDIS_REGISTER_ZMM12, Registers::ZMM12 },
    { ZYDIS_REGISTER_ZMM13, Registers::ZMM13 },
    { ZYDIS_REGISTER_ZMM14, Registers::ZMM14 },
    { ZYDIS_REGISTER_ZMM15, Registers::ZMM15 },
    { ZYDIS_REGISTER_ZMM16, Registers::ZMM16 },
    { ZYDIS_REGISTER_ZMM17, Registers::ZMM17 },
    { ZYDIS_REGISTER_ZMM18, Registers::ZMM18 },
    { ZYDIS_REGISTER_ZMM19, Registers::ZMM19 },
    { ZYDIS_REGISTER_ZMM20, Registers::ZMM20 },
    { ZYDIS_REGISTER_ZMM21, Registers::ZMM21 },
    { ZYDIS_REGISTER_ZMM22, Registers::ZMM22 },
    { ZYDIS_REGISTER_ZMM23, Registers::ZMM23 },
    { ZYDIS_REGISTER_ZMM24, Registers::ZMM24 },
    { ZYDIS_REGISTER_ZMM25, Registers::ZMM25 },
    { ZYDIS_REGISTER_ZMM26, Registers::ZMM26 },
    { ZYDIS_REGISTER_ZMM27, Registers::ZMM27 },
    { ZYDIS_REGISTER_ZMM28, Registers::ZMM28 },
    { ZYDIS_REGISTER_ZMM29, Registers::ZMM29 },
    { ZYDIS_REGISTER_ZMM30, Registers::ZMM30 },
    { ZYDIS_REGISTER_ZMM31, Registers::ZMM31 },
    { ZYDIS_REGISTER_RFLAGS, Registers::RFLAGS },
};

const std::unordered_map<ZydisRegister, ZydisRegister>
    Registers::reg_promotion_map_{
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

const std::unordered_set<ZydisRegister> Registers::legacy_ho_part_{
    ZYDIS_REGISTER_AH,
    ZYDIS_REGISTER_CH,
    ZYDIS_REGISTER_DH,
    ZYDIS_REGISTER_BH,
};

Registers::Registers(Registers const *parent)
    : holder_(parent ? parent->holder_ : std::make_shared<Holder>())
{
    if (parent == nullptr) {
        initialize_holder(*std::static_pointer_cast<Holder>(holder_),
                          0,
                          REGISTERS_COUNT);
    }
}

std::optional<Value> Registers::get(ZydisRegister zydis_reg) const
{
    zydis_reg = promote(zydis_reg);
    Reg reg;
    if (auto it = register_map.find(zydis_reg); it != register_map.end()) {
        reg = it->second;
    }
    else {
        return std::nullopt;
    }
    auto tree = std::static_pointer_cast<Holder>(holder_);
    size_t begin = 0;
    size_t end = REGISTERS_COUNT;
    while (true) {
        size_t middle = begin + (end - begin) / 2;
        if (reg < middle) {
            end = middle;
            if (begin < end - 1) {
                tree = std::static_pointer_cast<Holder>(tree->l);
            }
            else {
                return *std::static_pointer_cast<Value>(tree->l);
            }
        }
        else {
            begin = middle;
            if (begin < end - 1) {
                tree = std::static_pointer_cast<Holder>(tree->r);
            }
            else {
                return *std::static_pointer_cast<Value>(tree->r);
            }
        }
    }
    return std::nullopt;
}

// TODO: use register size
void Registers::set(ZydisRegister zydis_reg, Value value)
{
    zydis_reg = promote(zydis_reg);
    Reg reg;
    if (auto it = register_map.find(zydis_reg); it != register_map.end()) {
        reg = it->second;
    }
    else {
        return;
    }
    if (!value.is_symbolic()) {
        switch (value.size()) {
        default:
        case 8:
        case 4: break;
        case 2:
            if (auto orig_value = get(zydis_reg);
                orig_value && !orig_value->is_symbolic()) {
                auto new_value = (orig_value->value() & 0xFFFFFFFFFFFF0000)
                                 | (value.value() & 0xFFFF);
                value = Value(value.source(), new_value);
            }
            break;
        case 1:
            if (auto orig_value = get(zydis_reg);
                orig_value && !orig_value->is_symbolic()) {
                auto new_value = orig_value->value();
                if (!legacy_ho_part_.contains(zydis_reg)) {
                    new_value = (new_value & 0xFFFFFFFFFFFFFF00)
                                | (value.value() & 0xFF);
                }
                else {
                    new_value = (new_value & 0xFFFFFFFFFFFF00FF)
                                | ((value.value() & 0xFF) << 8);
                }
                value = Value(value.source(), new_value);
            }
            break;
        }
    }
    auto tree = std::static_pointer_cast<Holder>(holder_);
    auto new_tree = std::make_shared<Holder>();
    holder_ = new_tree;
    size_t begin = 0;
    size_t end = REGISTERS_COUNT;
    while (true) {
        size_t middle = begin + (end - begin) / 2;
        if (reg < middle) {
            end = middle;
            new_tree->r = tree->r;
            if (begin < end - 1) {
                new_tree->l = std::make_shared<Holder>();
                new_tree = std::static_pointer_cast<Holder>(new_tree->l);
                tree = std::static_pointer_cast<Holder>(tree->l);
            }
            else {
                new_tree->l = std::make_shared<Value>(std::move(value));
                break;
            }
        }
        else {
            begin = middle;
            new_tree->l = tree->l;
            if (begin < end - 1) {
                new_tree->r = std::make_shared<Holder>();
                new_tree = std::static_pointer_cast<Holder>(new_tree->r);
                tree = std::static_pointer_cast<Holder>(tree->r);
            }
            else {
                new_tree->r = std::make_shared<Value>(std::move(value));
                break;
            }
        }
    }
}

bool Registers::is_tracked(ZydisRegister zydis_reg) const
{
    zydis_reg = promote(zydis_reg);
    return register_map.contains(zydis_reg);
}

std::optional<Registers::Reg> Registers::from_zydis(ZydisRegister zydis_reg)
{
    zydis_reg = promote(zydis_reg);
    if (auto it = register_map.find(zydis_reg); it != register_map.end()) {
        return it->second;
    }
    return std::nullopt;
}

ZydisRegister Registers::promote(ZydisRegister zydis_reg)
{
    if (auto it = reg_promotion_map_.find(zydis_reg);
        it != reg_promotion_map_.end()) {
        zydis_reg = it->second;
    }
    return zydis_reg;
}

void Registers::initialize_holder(Holder &holder, size_t begin, size_t end)
{
    auto middle = begin + (end - begin) / 2;
    if (begin < middle - 1) {
        auto l = std::make_shared<Holder>();
        holder.l = l;
        initialize_holder(*l, begin, middle);
    }
    else {
        holder.l = std::make_shared<Value>();
    }
    if (middle < end - 1) {
        auto r = std::make_shared<Holder>();
        holder.r = r;
        initialize_holder(*r, middle, end);
    }
    else {
        holder.r = std::make_shared<Value>();
    }
}
