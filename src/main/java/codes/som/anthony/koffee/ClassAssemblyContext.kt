package codes.som.anthony.koffee

import org.objectweb.asm.Opcodes.ASM7
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.MethodNode
import kotlin.properties.Delegates

class ClassAssemblyContext : TypesAccess, ModifiersAccess {
    val node: ClassNode = ClassNode(ASM7).also {
        it.version = 49
        it.superName = "java/lang/Object"
    }

    var access: Modifiers
        get() = Modifiers(node.access)
        set(value) { node.access = value.access }

    var name: String
        get() = node.name
        set(value) { node.name = value }

    var version: Int
        get() = node.version
        set(value) { node.version = value }

    var superClass: Type
        get() = type(node.superName)
        set(value) { node.superName = value.internalName }

    val interfaces: MutableList<String>
        get() = node.interfaces

    val self get() = type(name)

    fun field(access: Modifiers, type: Type, name: String, signature: String? = null, value: Any? = null): FieldNode {
        val fieldNode = FieldNode(ASM7, access.access, name, type.descriptor, signature, value)
        node.fields.add(fieldNode)
        return fieldNode
    }

    fun method(access: Modifiers, name: String,
               returnType: Type, vararg parameterTypes: Type,
               signature: String? = null, exceptions: Array<Type>? = null,
               routine: MethodAssemblyContext.() -> Unit): MethodNode {
        val descriptor = Type.getMethodDescriptor(returnType, *parameterTypes)

        val methodNode = MethodNode(ASM7, access.access, name, descriptor, signature, exceptions?.map { it.internalName }?.toTypedArray())
        val methodAssemblyContext = MethodAssemblyContext(methodNode)
        routine(methodAssemblyContext)

        node.methods.add(methodNode)

        return methodNode
    }
}
