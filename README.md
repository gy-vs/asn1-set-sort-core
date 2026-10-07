# ASN.1 DER core

一个零运行时依赖的 DER（X.690）编解码库：先用 builder 描述结构，再把普通 JS
对象编码成字节，或把字节严格解码回对象。编解码两边对“什么是合法 DER”的
说法完全一致——编码器的产物一定能被严格解码器收下，解码器收下的内容重新
编码得到原样字节。

## 安装与检查

```sh
npm install
npm test      # vitest
npm run build # tsc -> dist/
```

## 用法

```ts
import {
  sequence, setOf, implicit, withDefault, optional,
  integer, utf8String, oid, encode, decode, Choice,
} from './dist/index.js';

const schema = sequence([
  ['version', withDefault(integer(), 0n)],
  ['name',    utf8String()],
  ['issuer',  optional(implicit(utf8String(), 1))],
  ['algo',    choice({oid: oid(), number: implicit(integer(), 0)})],
  ['policies', setOf(oid())],
]);

const der = encode(schema, {
  name: 'root',
  algo: {[Choice]: 'number', value: 1n},
  policies: ['2.5.4.3', '1.2.3'], // 调用方给什么顺序都行
});

const obj = decode(schema, der);   // 严格模式（默认）
```

### 类型与 JS 值的对应

| ASN.1 类型 | JS 值 |
| --- | --- |
| `BOOLEAN` | `boolean` |
| `INTEGER` | `bigint` |
| `BIT STRING` | `{ unused: number, data: Uint8Array }` |
| `OCTET STRING` | `Uint8Array` |
| `NULL` | `null`（builder 叫 `nullType()`） |
| `OBJECT IDENTIFIER` | 点分字符串 `'1.2.840.113549'` |
| `UTF8String` | `string` |
| `SEQUENCE` / `SET` | 普通对象（按字段名） |
| `SEQUENCE OF` / `SET OF` | 数组 |
| `CHOICE` | `{ [Choice]: '分支名', value: ... }` |

字段标记：`optional(schema)`、`withDefault(schema, 默认值)`；
上下文标签：`implicit(schema, n)`、`explicit(schema, n)`。

## 唯一性保证

- 长度只用定长最短形式；INTEGER 内容是最短二进制补码；BOOLEAN 只有
  `0x00`/`0xFF`；BIT STRING 未用位强制清零。
- 等于 DEFAULT 的字段不写出。
- SET / SET OF 的全部组件按完整编码字节升序（X.690 §11.6）输出，与调用方
  给的顺序无关，嵌套 SET OF 同样如此。

## 严格解码

`decode(schema, bytes)` 默认严格，任何不是 DER 唯一形式的输入都会抛
`Asn1Error`，包括：不定长、长度冗余字节、INTEGER 多余符号扩展、非规范
BOOLEAN/NULL/BIT STRING/OID、SET(OF) 未排序、显式写出 DEFAULT 值、
SEQUENCE 字段乱序、尾部多余字节等。错误带 `offset`（字节偏移）和 `path`
（如 `certs[3].validity.notAfter`）。

`decode(schema, bytes, { strict: false })` 接受少数 BER 松弛形式（重新编码
仍会规范化）；不定长和构造式原语始终不支持。

## 资源与攻击面

- `decode` 的 `maxDepth`（默认 256）限制嵌套深度，超限报明确错误而不是
  打爆调用栈；`encode` 同名选项同样生效。
- 所有边界按实际剩余字节校验；声明长度远大于实际输入时立即失败，内存不随
  声明长度增长。
- 十万级元素的 SET OF 编解码各在普通笔记本上约 1 秒内完成。
