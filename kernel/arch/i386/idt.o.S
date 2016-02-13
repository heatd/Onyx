	.file	"idt.cpp"
	.text
.Ltext0:
	.section	.text.unlikely,"ax",@progbits
.LCOLDB0:
	.text
.LHOTB0:
	.align 16
	.section	.text.unlikely
.Ltext_cold0:
	.text
	.globl	_Z8init_idtv
	.type	_Z8init_idtv, @function
_Z8init_idtv:
.LFB0:
	.file 1 "arch/i386/idt.cpp"
	.loc 1 21 0
	.cfi_startproc
	pushl	%edi
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	.loc 1 22 0
	movl	$idt_entries, %edx
	xorl	%eax, %eax
	movl	%edx, %edi
	movl	$512, %ecx
	.loc 1 21 0
	subl	$20, %esp
	.cfi_def_cfa_offset 28
	.loc 1 22 0
	rep stosl
	.loc 1 24 0
	movl	$isr0, %eax
.LVL0:
.LBB102:
.LBB103:
	.loc 1 82 0
	movl	$8, %ecx
.LBE103:
.LBE102:
.LBB106:
.LBB107:
	movl	$8, %edi
.LBE107:
.LBE106:
.LBB111:
.LBB112:
	.loc 1 79 0
	movw	%ax, idt_entries
	.loc 1 80 0
	shrl	$16, %eax
.LBE112:
.LBE111:
.LBB116:
.LBB104:
	.loc 1 82 0
	movw	%cx, idt_entries+10
.LBE104:
.LBE116:
.LBB117:
.LBB113:
	.loc 1 80 0
	movw	%ax, idt_entries+6
	.loc 1 82 0
	movl	$8, %eax
.LBE113:
.LBE117:
.LBB118:
.LBB108:
	movw	%di, idt_entries+18
.LBE108:
.LBE118:
.LBB119:
.LBB114:
	movw	%ax, idt_entries+2
.LBE114:
.LBE119:
	.loc 1 25 0
	movl	$isr1, %eax
.LBB120:
.LBB115:
	.loc 1 85 0
	movb	$-18, idt_entries+5
.LVL1:
.LBE115:
.LBE120:
.LBB121:
.LBB105:
	.loc 1 79 0
	movw	%ax, idt_entries+8
	.loc 1 80 0
	shrl	$16, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+13
.LVL2:
	.loc 1 80 0
	movw	%ax, idt_entries+14
.LBE105:
.LBE121:
	.loc 1 26 0
	movl	$isr2, %eax
.LVL3:
.LBB122:
.LBB109:
	.loc 1 85 0
	movb	$-18, idt_entries+21
.LVL4:
	.loc 1 79 0
	movw	%ax, idt_entries+16
	.loc 1 80 0
	shrl	$16, %eax
.LBE109:
.LBE122:
.LBB123:
.LBB124:
	.loc 1 85 0
	movb	$-18, idt_entries+29
.LBE124:
.LBE123:
.LBB128:
.LBB110:
	.loc 1 80 0
	movw	%ax, idt_entries+22
.LBE110:
.LBE128:
	.loc 1 27 0
	movl	$isr3, %eax
.LVL5:
.LBB129:
.LBB130:
	.loc 1 85 0
	movb	$-18, idt_entries+37
.LBE130:
.LBE129:
.LBB133:
.LBB125:
	.loc 1 79 0
	movw	%ax, idt_entries+24
	.loc 1 80 0
	shrl	$16, %eax
.LBE125:
.LBE133:
.LBB134:
.LBB135:
	.loc 1 85 0
	movb	$-18, idt_entries+45
.LBE135:
.LBE134:
.LBB137:
.LBB126:
	.loc 1 80 0
	movw	%ax, idt_entries+30
	.loc 1 82 0
	movl	$8, %eax
.LBE126:
.LBE137:
.LBB138:
.LBB139:
	.loc 1 85 0
	movb	$-18, idt_entries+53
.LBE139:
.LBE138:
.LBB141:
.LBB127:
	.loc 1 82 0
	movw	%ax, idt_entries+26
.LBE127:
.LBE141:
	.loc 1 28 0
	movl	$isr4, %eax
.LVL6:
.LBB142:
.LBB143:
	.loc 1 82 0
	movl	$8, %ecx
.LBE143:
.LBE142:
.LBB147:
.LBB131:
	.loc 1 79 0
	movw	%ax, idt_entries+32
	.loc 1 80 0
	shrl	$16, %eax
.LBE131:
.LBE147:
.LBB148:
.LBB149:
	.loc 1 82 0
	movl	$8, %edi
.LBE149:
.LBE148:
.LBB154:
.LBB132:
	.loc 1 80 0
	movw	%ax, idt_entries+38
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+34
.LBE132:
.LBE154:
	.loc 1 29 0
	movl	$isr5, %eax
.LVL7:
.LBB155:
.LBB136:
	.loc 1 79 0
	movw	%ax, idt_entries+40
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+46
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+42
.LBE136:
.LBE155:
	.loc 1 30 0
	movl	$isr6, %eax
.LVL8:
.LBB156:
.LBB140:
	.loc 1 79 0
	movw	%ax, idt_entries+48
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+54
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+50
.LBE140:
.LBE156:
	.loc 1 31 0
	movl	$isr7, %eax
.LVL9:
.LBB157:
.LBB158:
	.loc 1 79 0
	movw	%ax, idt_entries+56
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+62
	.loc 1 82 0
	movl	$8, %eax
.LBE158:
.LBE157:
.LBB161:
.LBB144:
	movw	%cx, idt_entries+74
.LBE144:
.LBE161:
.LBB162:
.LBB159:
	movw	%ax, idt_entries+58
.LBE159:
.LBE162:
	.loc 1 32 0
	movl	$isr8, %eax
.LBB163:
.LBB150:
	.loc 1 82 0
	movw	%di, idt_entries+82
.LBE150:
.LBE163:
.LBB164:
.LBB165:
	.loc 1 79 0
	movw	%ax, idt_entries+64
	.loc 1 80 0
	shrl	$16, %eax
.LBE165:
.LBE164:
.LBB167:
.LBB160:
	.loc 1 85 0
	movb	$-18, idt_entries+61
.LVL10:
.LBE160:
.LBE167:
.LBB168:
.LBB166:
	.loc 1 80 0
	movw	%ax, idt_entries+70
	.loc 1 82 0
	movl	$8, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+69
.LVL11:
	.loc 1 82 0
	movw	%ax, idt_entries+66
.LBE166:
.LBE168:
	.loc 1 33 0
	movl	$isr9, %eax
.LVL12:
.LBB169:
.LBB145:
	.loc 1 85 0
	movb	$-18, idt_entries+77
.LVL13:
	.loc 1 79 0
	movw	%ax, idt_entries+72
	.loc 1 80 0
	shrl	$16, %eax
.LBE145:
.LBE169:
.LBB170:
.LBB151:
	.loc 1 85 0
	movb	$-18, idt_entries+85
.LBE151:
.LBE170:
.LBB171:
.LBB146:
	.loc 1 80 0
	movw	%ax, idt_entries+78
.LBE146:
.LBE171:
	.loc 1 34 0
	movl	$isr10, %eax
.LVL14:
.LBB172:
.LBB173:
	.loc 1 85 0
	movb	$-18, idt_entries+93
.LBE173:
.LBE172:
.LBB177:
.LBB152:
	.loc 1 79 0
	movw	%ax, idt_entries+80
	.loc 1 80 0
	shrl	$16, %eax
.LBE152:
.LBE177:
.LBB178:
.LBB179:
	.loc 1 85 0
	movb	$-18, idt_entries+101
.LBE179:
.LBE178:
.LBB181:
.LBB153:
	.loc 1 80 0
	movw	%ax, idt_entries+86
.LBE153:
.LBE181:
	.loc 1 35 0
	movl	$isr11, %eax
.LVL15:
.LBB182:
.LBB183:
	.loc 1 85 0
	movb	$-18, idt_entries+109
.LBE183:
.LBE182:
.LBB185:
.LBB174:
	.loc 1 79 0
	movw	%ax, idt_entries+88
	.loc 1 80 0
	shrl	$16, %eax
.LBE174:
.LBE185:
.LBB186:
.LBB187:
	.loc 1 85 0
	movb	$-18, idt_entries+117
.LBE187:
.LBE186:
.LBB189:
.LBB175:
	.loc 1 80 0
	movw	%ax, idt_entries+94
	.loc 1 82 0
	movl	$8, %eax
.LBE175:
.LBE189:
.LBB190:
.LBB191:
	movl	$8, %ecx
.LBE191:
.LBE190:
.LBB194:
.LBB176:
	movw	%ax, idt_entries+90
.LBE176:
.LBE194:
	.loc 1 36 0
	movl	$isr12, %eax
.LVL16:
.LBB195:
.LBB196:
	.loc 1 82 0
	movl	$8, %edi
.LBE196:
.LBE195:
.LBB200:
.LBB180:
	.loc 1 79 0
	movw	%ax, idt_entries+96
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+102
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+98
.LBE180:
.LBE200:
	.loc 1 37 0
	movl	$isr13, %eax
.LVL17:
.LBB201:
.LBB184:
	.loc 1 79 0
	movw	%ax, idt_entries+104
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+110
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+106
.LBE184:
.LBE201:
	.loc 1 38 0
	movl	$isr14, %eax
.LVL18:
.LBB202:
.LBB188:
	.loc 1 79 0
	movw	%ax, idt_entries+112
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+118
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+114
.LBE188:
.LBE202:
	.loc 1 39 0
	movl	$isr15, %eax
.LVL19:
.LBB203:
.LBB204:
	.loc 1 79 0
	movw	%ax, idt_entries+120
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+126
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+122
.LBE204:
.LBE203:
	.loc 1 40 0
	movl	$isr16, %eax
.LBB206:
.LBB192:
	.loc 1 82 0
	movw	%cx, idt_entries+138
.LBE192:
.LBE206:
.LBB207:
.LBB208:
	.loc 1 79 0
	movw	%ax, idt_entries+128
	.loc 1 80 0
	shrl	$16, %eax
.LBE208:
.LBE207:
.LBB212:
.LBB197:
	.loc 1 82 0
	movw	%di, idt_entries+146
.LBE197:
.LBE212:
.LBB213:
.LBB209:
	.loc 1 80 0
	movw	%ax, idt_entries+134
	.loc 1 82 0
	movl	$8, %eax
.LBE209:
.LBE213:
.LBB214:
.LBB205:
	.loc 1 85 0
	movb	$-18, idt_entries+125
.LVL20:
.LBE205:
.LBE214:
.LBB215:
.LBB210:
	.loc 1 82 0
	movw	%ax, idt_entries+130
.LBE210:
.LBE215:
	.loc 1 41 0
	movl	$isr17, %eax
.LBB216:
.LBB211:
	.loc 1 85 0
	movb	$-18, idt_entries+133
.LVL21:
.LBE211:
.LBE216:
.LBB217:
.LBB193:
	.loc 1 79 0
	movw	%ax, idt_entries+136
	.loc 1 80 0
	shrl	$16, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+141
.LVL22:
	.loc 1 80 0
	movw	%ax, idt_entries+142
.LBE193:
.LBE217:
	.loc 1 42 0
	movl	$isr18, %eax
.LVL23:
.LBB218:
.LBB198:
	.loc 1 85 0
	movb	$-18, idt_entries+149
.LVL24:
	.loc 1 79 0
	movw	%ax, idt_entries+144
	.loc 1 80 0
	shrl	$16, %eax
.LBE198:
.LBE218:
.LBB219:
.LBB220:
	.loc 1 85 0
	movb	$-18, idt_entries+157
.LBE220:
.LBE219:
.LBB224:
.LBB199:
	.loc 1 80 0
	movw	%ax, idt_entries+150
.LBE199:
.LBE224:
	.loc 1 43 0
	movl	$isr19, %eax
.LVL25:
.LBB225:
.LBB226:
	.loc 1 85 0
	movb	$-18, idt_entries+165
.LBE226:
.LBE225:
.LBB229:
.LBB221:
	.loc 1 79 0
	movw	%ax, idt_entries+152
	.loc 1 80 0
	shrl	$16, %eax
.LBE221:
.LBE229:
.LBB230:
.LBB231:
	.loc 1 85 0
	movb	$-18, idt_entries+173
.LBE231:
.LBE230:
.LBB233:
.LBB222:
	.loc 1 80 0
	movw	%ax, idt_entries+158
	.loc 1 82 0
	movl	$8, %eax
.LBE222:
.LBE233:
.LBB234:
.LBB235:
	.loc 1 85 0
	movb	$-18, idt_entries+181
.LBE235:
.LBE234:
.LBB237:
.LBB223:
	.loc 1 82 0
	movw	%ax, idt_entries+154
.LBE223:
.LBE237:
	.loc 1 44 0
	movl	$isr20, %eax
.LVL26:
.LBB238:
.LBB239:
	.loc 1 82 0
	movl	$8, %ecx
.LBE239:
.LBE238:
.LBB242:
.LBB227:
	.loc 1 79 0
	movw	%ax, idt_entries+160
	.loc 1 80 0
	shrl	$16, %eax
.LBE227:
.LBE242:
.LBB243:
.LBB244:
	.loc 1 82 0
	movl	$8, %edi
.LBE244:
.LBE243:
.LBB248:
.LBB228:
	.loc 1 80 0
	movw	%ax, idt_entries+166
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+162
.LBE228:
.LBE248:
	.loc 1 45 0
	movl	$isr21, %eax
.LVL27:
.LBB249:
.LBB232:
	.loc 1 79 0
	movw	%ax, idt_entries+168
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+174
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+170
.LBE232:
.LBE249:
	.loc 1 46 0
	movl	$isr22, %eax
.LVL28:
.LBB250:
.LBB236:
	.loc 1 79 0
	movw	%ax, idt_entries+176
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+182
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+178
.LBE236:
.LBE250:
	.loc 1 47 0
	movl	$isr23, %eax
.LVL29:
.LBB251:
.LBB252:
	.loc 1 79 0
	movw	%ax, idt_entries+184
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+190
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+186
.LBE252:
.LBE251:
	.loc 1 48 0
	movl	$isr24, %eax
.LBB254:
.LBB253:
	.loc 1 85 0
	movb	$-18, idt_entries+189
.LVL30:
.LBE253:
.LBE254:
.LBB255:
.LBB256:
	.loc 1 79 0
	movw	%ax, idt_entries+192
	.loc 1 80 0
	shrl	$16, %eax
.LBE256:
.LBE255:
.LBB260:
.LBB240:
	.loc 1 82 0
	movw	%cx, idt_entries+202
.LBE240:
.LBE260:
.LBB261:
.LBB257:
	.loc 1 80 0
	movw	%ax, idt_entries+198
	.loc 1 82 0
	movl	$8, %eax
.LBE257:
.LBE261:
.LBB262:
.LBB245:
	movw	%di, idt_entries+210
.LBE245:
.LBE262:
.LBB263:
.LBB258:
	movw	%ax, idt_entries+194
.LBE258:
.LBE263:
	.loc 1 49 0
	movl	$isr25, %eax
.LBB264:
.LBB259:
	.loc 1 85 0
	movb	$-18, idt_entries+197
.LVL31:
.LBE259:
.LBE264:
.LBB265:
.LBB241:
	.loc 1 79 0
	movw	%ax, idt_entries+200
	.loc 1 80 0
	shrl	$16, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+205
.LVL32:
	.loc 1 80 0
	movw	%ax, idt_entries+206
.LBE241:
.LBE265:
	.loc 1 50 0
	movl	$isr26, %eax
.LVL33:
.LBB266:
.LBB246:
	.loc 1 85 0
	movb	$-18, idt_entries+213
.LVL34:
	.loc 1 79 0
	movw	%ax, idt_entries+208
	.loc 1 80 0
	shrl	$16, %eax
.LBE246:
.LBE266:
.LBB267:
.LBB268:
	.loc 1 85 0
	movb	$-18, idt_entries+221
.LBE268:
.LBE267:
.LBB272:
.LBB247:
	.loc 1 80 0
	movw	%ax, idt_entries+214
.LBE247:
.LBE272:
	.loc 1 51 0
	movl	$isr27, %eax
.LVL35:
.LBB273:
.LBB274:
	.loc 1 85 0
	movb	$-18, idt_entries+229
.LBE274:
.LBE273:
.LBB278:
.LBB269:
	.loc 1 79 0
	movw	%ax, idt_entries+216
	.loc 1 80 0
	shrl	$16, %eax
.LBE269:
.LBE278:
.LBB279:
.LBB280:
	.loc 1 85 0
	movb	$-18, idt_entries+237
.LBE280:
.LBE279:
.LBB282:
.LBB270:
	.loc 1 80 0
	movw	%ax, idt_entries+222
	.loc 1 82 0
	movl	$8, %eax
.LBE270:
.LBE282:
.LBB283:
.LBB284:
	.loc 1 85 0
	movb	$-18, idt_entries+245
.LBE284:
.LBE283:
.LBB286:
.LBB271:
	.loc 1 82 0
	movw	%ax, idt_entries+218
.LBE271:
.LBE286:
	.loc 1 52 0
	movl	$isr28, %eax
.LVL36:
.LBB287:
.LBB288:
	.loc 1 85 0
	movb	$-18, idt_entries+253
.LBE288:
.LBE287:
.LBB290:
.LBB275:
	.loc 1 79 0
	movw	%ax, idt_entries+224
	.loc 1 80 0
	shrl	$16, %eax
.LBE275:
.LBE290:
.LBB291:
.LBB292:
	.loc 1 82 0
	movl	$8, %ecx
.LBE292:
.LBE291:
.LBB295:
.LBB276:
	.loc 1 80 0
	movw	%ax, idt_entries+230
	.loc 1 82 0
	movl	$8, %eax
.LBE276:
.LBE295:
.LBB296:
.LBB297:
	movl	$8, %edi
.LBE297:
.LBE296:
.LBB301:
.LBB277:
	movw	%ax, idt_entries+226
.LBE277:
.LBE301:
	.loc 1 53 0
	movl	$isr29, %eax
.LVL37:
.LBB302:
.LBB281:
	.loc 1 79 0
	movw	%ax, idt_entries+232
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+238
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+234
.LBE281:
.LBE302:
	.loc 1 54 0
	movl	$isr30, %eax
.LVL38:
.LBB303:
.LBB285:
	.loc 1 79 0
	movw	%ax, idt_entries+240
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+246
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+242
.LBE285:
.LBE303:
	.loc 1 55 0
	movl	$isr31, %eax
.LVL39:
.LBB304:
.LBB289:
	.loc 1 79 0
	movw	%ax, idt_entries+248
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+254
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+250
.LBE289:
.LBE304:
	.loc 1 56 0
	movl	$irq0, %eax
.LVL40:
.LBB305:
.LBB306:
	.loc 1 79 0
	movw	%ax, idt_entries+256
	.loc 1 80 0
	shrl	$16, %eax
.LBE306:
.LBE305:
.LBB310:
.LBB293:
	.loc 1 82 0
	movw	%cx, idt_entries+266
.LBE293:
.LBE310:
.LBB311:
.LBB307:
	.loc 1 80 0
	movw	%ax, idt_entries+262
	.loc 1 82 0
	movl	$8, %eax
.LBE307:
.LBE311:
.LBB312:
.LBB298:
	movw	%di, idt_entries+274
.LBE298:
.LBE312:
.LBB313:
.LBB308:
	movw	%ax, idt_entries+258
.LBE308:
.LBE313:
	.loc 1 57 0
	movl	$irq1, %eax
.LBB314:
.LBB309:
	.loc 1 85 0
	movb	$-18, idt_entries+261
.LVL41:
.LBE309:
.LBE314:
.LBB315:
.LBB294:
	.loc 1 79 0
	movw	%ax, idt_entries+264
	.loc 1 80 0
	shrl	$16, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+269
.LVL42:
	.loc 1 80 0
	movw	%ax, idt_entries+270
.LBE294:
.LBE315:
	.loc 1 58 0
	movl	$irq2, %eax
.LVL43:
.LBB316:
.LBB299:
	.loc 1 85 0
	movb	$-18, idt_entries+277
.LVL44:
	.loc 1 79 0
	movw	%ax, idt_entries+272
	.loc 1 80 0
	shrl	$16, %eax
.LBE299:
.LBE316:
.LBB317:
.LBB318:
	.loc 1 85 0
	movb	$-18, idt_entries+285
.LBE318:
.LBE317:
.LBB322:
.LBB300:
	.loc 1 80 0
	movw	%ax, idt_entries+278
.LBE300:
.LBE322:
	.loc 1 59 0
	movl	$irq3, %eax
.LVL45:
.LBB323:
.LBB324:
	.loc 1 85 0
	movb	$-18, idt_entries+293
.LBE324:
.LBE323:
.LBB328:
.LBB319:
	.loc 1 79 0
	movw	%ax, idt_entries+280
	.loc 1 80 0
	shrl	$16, %eax
.LBE319:
.LBE328:
.LBB329:
.LBB330:
	.loc 1 85 0
	movb	$-18, idt_entries+301
.LBE330:
.LBE329:
.LBB332:
.LBB320:
	.loc 1 80 0
	movw	%ax, idt_entries+286
	.loc 1 82 0
	movl	$8, %eax
.LBE320:
.LBE332:
.LBB333:
.LBB334:
	.loc 1 85 0
	movb	$-18, idt_entries+309
.LBE334:
.LBE333:
.LBB336:
.LBB321:
	.loc 1 82 0
	movw	%ax, idt_entries+282
.LBE321:
.LBE336:
	.loc 1 60 0
	movl	$irq4, %eax
.LVL46:
.LBB337:
.LBB338:
	.loc 1 85 0
	movb	$-18, idt_entries+317
.LBE338:
.LBE337:
.LBB340:
.LBB325:
	.loc 1 79 0
	movw	%ax, idt_entries+288
	.loc 1 80 0
	shrl	$16, %eax
.LBE325:
.LBE340:
.LBB341:
.LBB342:
	.loc 1 82 0
	movl	$8, %ecx
.LBE342:
.LBE341:
.LBB347:
.LBB326:
	.loc 1 80 0
	movw	%ax, idt_entries+294
	.loc 1 82 0
	movl	$8, %eax
.LBE326:
.LBE347:
.LBB348:
.LBB349:
	movl	$8, %edi
.LBE349:
.LBE348:
.LBB352:
.LBB327:
	movw	%ax, idt_entries+290
.LBE327:
.LBE352:
	.loc 1 61 0
	movl	$irq5, %eax
.LVL47:
.LBB353:
.LBB331:
	.loc 1 79 0
	movw	%ax, idt_entries+296
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+302
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+298
.LBE331:
.LBE353:
	.loc 1 62 0
	movl	$irq6, %eax
.LVL48:
.LBB354:
.LBB335:
	.loc 1 79 0
	movw	%ax, idt_entries+304
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+310
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+306
.LBE335:
.LBE354:
	.loc 1 63 0
	movl	$irq7, %eax
.LVL49:
.LBB355:
.LBB339:
	.loc 1 79 0
	movw	%ax, idt_entries+312
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+318
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+314
.LBE339:
.LBE355:
	.loc 1 64 0
	movl	$irq8, %eax
.LVL50:
.LBB356:
.LBB357:
	.loc 1 79 0
	movw	%ax, idt_entries+320
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+326
	.loc 1 82 0
	movl	$8, %eax
.LBE357:
.LBE356:
.LBB360:
.LBB343:
	movw	%cx, idt_entries+330
.LBE343:
.LBE360:
.LBB361:
.LBB358:
	movw	%ax, idt_entries+322
.LBE358:
.LBE361:
	.loc 1 65 0
	movl	$irq9, %eax
.LBB362:
.LBB350:
	.loc 1 82 0
	movw	%di, idt_entries+338
.LBE350:
.LBE362:
.LBB363:
.LBB344:
	.loc 1 79 0
	movw	%ax, idt_entries+328
	.loc 1 80 0
	shrl	$16, %eax
.LBE344:
.LBE363:
.LBB364:
.LBB359:
	.loc 1 85 0
	movb	$-18, idt_entries+325
.LVL51:
.LBE359:
.LBE364:
.LBB365:
.LBB345:
	.loc 1 80 0
	movw	%ax, idt_entries+334
.LBE345:
.LBE365:
	.loc 1 66 0
	movl	$irq10, %eax
.LBB366:
.LBB346:
	.loc 1 85 0
	movb	$-18, idt_entries+333
.LVL52:
.LBE346:
.LBE366:
.LBB367:
.LBB351:
	.loc 1 79 0
	movw	%ax, idt_entries+336
	.loc 1 80 0
	shrl	$16, %eax
	.loc 1 85 0
	movb	$-18, idt_entries+341
.LVL53:
	.loc 1 80 0
	movw	%ax, idt_entries+342
.LBE351:
.LBE367:
	.loc 1 67 0
	movl	$irq11, %eax
.LVL54:
.LBB368:
.LBB369:
	.loc 1 85 0
	movb	$-18, idt_entries+349
.LVL55:
	.loc 1 79 0
	movw	%ax, idt_entries+344
	.loc 1 80 0
	shrl	$16, %eax
.LBE369:
.LBE368:
.LBB372:
.LBB373:
	.loc 1 85 0
	movb	$-18, idt_entries+357
.LBE373:
.LBE372:
.LBB377:
.LBB370:
	.loc 1 80 0
	movw	%ax, idt_entries+350
	.loc 1 82 0
	movl	$8, %eax
.LBE370:
.LBE377:
.LBB378:
.LBB379:
	.loc 1 85 0
	movb	$-18, idt_entries+365
.LBE379:
.LBE378:
.LBB381:
.LBB371:
	.loc 1 82 0
	movw	%ax, idt_entries+346
.LBE371:
.LBE381:
	.loc 1 68 0
	movl	$irq12, %eax
.LVL56:
.LBB382:
.LBB383:
	.loc 1 85 0
	movb	$-18, idt_entries+373
.LBE383:
.LBE382:
.LBB385:
.LBB374:
	.loc 1 79 0
	movw	%ax, idt_entries+352
	.loc 1 80 0
	shrl	$16, %eax
.LBE374:
.LBE385:
.LBB386:
.LBB387:
	.loc 1 85 0
	movb	$-18, idt_entries+381
.LBE387:
.LBE386:
.LBB389:
.LBB375:
	.loc 1 80 0
	movw	%ax, idt_entries+358
	.loc 1 82 0
	movl	$8, %eax
.LBE375:
.LBE389:
.LBB390:
.LBB391:
	.loc 1 90 0
	movl	$2047, %ecx
.LBE391:
.LBE390:
.LBB394:
.LBB376:
	.loc 1 82 0
	movw	%ax, idt_entries+354
.LBE376:
.LBE394:
	.loc 1 69 0
	movl	$irq13, %eax
.LVL57:
.LBB395:
.LBB380:
	.loc 1 79 0
	movw	%ax, idt_entries+360
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+366
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+362
.LBE380:
.LBE395:
	.loc 1 70 0
	movl	$irq14, %eax
.LVL58:
.LBB396:
.LBB384:
	.loc 1 79 0
	movw	%ax, idt_entries+368
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+374
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+370
.LBE384:
.LBE396:
	.loc 1 71 0
	movl	$irq15, %eax
.LVL59:
.LBB397:
.LBB388:
	.loc 1 79 0
	movw	%ax, idt_entries+376
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+382
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+378
.LBE388:
.LBE397:
	.loc 1 73 0
	movl	$_syscall, %eax
.LVL60:
.LBB398:
.LBB399:
	.loc 1 79 0
	movw	%ax, idt_entries+1024
	.loc 1 80 0
	shrl	$16, %eax
	movw	%ax, idt_entries+1030
	.loc 1 82 0
	movl	$8, %eax
	movw	%ax, idt_entries+1026
.LBE399:
.LBE398:
.LBB401:
.LBB392:
	.loc 1 92 0
	pushl	$idt_ptr
	.cfi_def_cfa_offset 32
.LBE392:
.LBE401:
.LBB402:
.LBB400:
	.loc 1 85 0
	movb	$-18, idt_entries+1029
.LVL61:
.LBE400:
.LBE402:
.LBB403:
.LBB393:
	.loc 1 90 0
	movw	%cx, idt_ptr
	.loc 1 91 0
	movl	%edx, idt_ptr+2
	.loc 1 92 0
	call	IDT_Flush
.LVL62:
.LBE393:
.LBE403:
	.loc 1 76 0
	addl	$24, %esp
	.cfi_def_cfa_offset 8
	popl	%edi
	.cfi_restore 7
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE0:
	.size	_Z8init_idtv, .-_Z8init_idtv
	.section	.text.unlikely
.LCOLDE0:
	.text
.LHOTE0:
	.section	.text.unlikely
.LCOLDB1:
	.text
.LHOTB1:
	.align 16
	.globl	_Z21idt_create_descriptorhmth
	.type	_Z21idt_create_descriptorhmth, @function
_Z21idt_create_descriptorhmth:
.LFB1:
	.loc 1 78 0
	.cfi_startproc
.LVL63:
	.loc 1 79 0
	movzbl	4(%esp), %eax
	.loc 1 78 0
	movl	8(%esp), %edx
	.loc 1 79 0
	movw	%dx, idt_entries(,%eax,8)
	.loc 1 80 0
	shrl	$16, %edx
	.loc 1 84 0
	movb	$0, idt_entries+4(,%eax,8)
	.loc 1 80 0
	movw	%dx, idt_entries+6(,%eax,8)
	.loc 1 82 0
	movl	12(%esp), %edx
	movw	%dx, idt_entries+2(,%eax,8)
	.loc 1 85 0
	movzbl	16(%esp), %edx
	orl	$96, %edx
	movb	%dl, idt_entries+5(,%eax,8)
	ret
	.cfi_endproc
.LFE1:
	.size	_Z21idt_create_descriptorhmth, .-_Z21idt_create_descriptorhmth
	.section	.text.unlikely
.LCOLDE1:
	.text
.LHOTE1:
	.section	.text.unlikely
.LCOLDB2:
	.text
.LHOTB2:
	.align 16
	.globl	_Z8load_idtv
	.type	_Z8load_idtv, @function
_Z8load_idtv:
.LFB2:
	.loc 1 89 0
	.cfi_startproc
	subl	$24, %esp
	.cfi_def_cfa_offset 28
	.loc 1 90 0
	movl	$2047, %eax
	.loc 1 91 0
	movl	$idt_entries, idt_ptr+2
	.loc 1 92 0
	pushl	$idt_ptr
	.cfi_def_cfa_offset 32
	.loc 1 90 0
	movw	%ax, idt_ptr
	.loc 1 92 0
	call	IDT_Flush
.LVL64:
	.loc 1 93 0
	addl	$28, %esp
	.cfi_def_cfa_offset 4
	ret
	.cfi_endproc
.LFE2:
	.size	_Z8load_idtv, .-_Z8load_idtv
	.section	.text.unlikely
.LCOLDE2:
	.text
.LHOTE2:
	.globl	idt_entries
	.section	.bss
	.align 32
	.type	idt_entries, @object
	.size	idt_entries, 2048
idt_entries:
	.zero	2048
	.globl	idt_ptr
	.align 4
	.type	idt_ptr, @object
	.size	idt_ptr, 6
idt_ptr:
	.zero	6
	.text
.Letext0:
	.section	.text.unlikely
.Letext_cold0:
	.file 2 "/home/pfalcato/i686-elf/lib/gcc/i686-elf/5.3.0/include/stdint-gcc.h"
	.file 3 "include/kernel/idt.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xad7
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF30
	.byte	0x4
	.long	.LASF31
	.long	.LASF32
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF1
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF2
	.uleb128 0x2
	.byte	0xc
	.byte	0x4
	.long	.LASF3
	.uleb128 0x3
	.long	.LASF33
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF5
	.uleb128 0x5
	.long	.LASF7
	.byte	0x2
	.byte	0x2e
	.long	0x66
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF6
	.uleb128 0x5
	.long	.LASF8
	.byte	0x2
	.byte	0x31
	.long	0x78
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x5
	.long	.LASF10
	.byte	0x2
	.byte	0x34
	.long	0x2c
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF11
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF12
	.uleb128 0x6
	.long	.LASF16
	.byte	0x6
	.byte	0x3
	.byte	0x14
	.long	0xbd
	.uleb128 0x7
	.long	.LASF13
	.byte	0x3
	.byte	0x16
	.long	0x6d
	.byte	0
	.uleb128 0x7
	.long	.LASF14
	.byte	0x3
	.byte	0x17
	.long	0x7f
	.byte	0x2
	.byte	0
	.uleb128 0x5
	.long	.LASF15
	.byte	0x3
	.byte	0x1a
	.long	0x98
	.uleb128 0x6
	.long	.LASF17
	.byte	0x8
	.byte	0x3
	.byte	0x1c
	.long	0x111
	.uleb128 0x7
	.long	.LASF18
	.byte	0x3
	.byte	0x1e
	.long	0x6d
	.byte	0
	.uleb128 0x7
	.long	.LASF19
	.byte	0x3
	.byte	0x1f
	.long	0x6d
	.byte	0x2
	.uleb128 0x7
	.long	.LASF20
	.byte	0x3
	.byte	0x20
	.long	0x5b
	.byte	0x4
	.uleb128 0x7
	.long	.LASF21
	.byte	0x3
	.byte	0x21
	.long	0x5b
	.byte	0x5
	.uleb128 0x7
	.long	.LASF22
	.byte	0x3
	.byte	0x22
	.long	0x6d
	.byte	0x6
	.byte	0
	.uleb128 0x8
	.long	.LASF34
	.byte	0x1
	.byte	0x58
	.long	.LASF27
	.byte	0x1
	.uleb128 0x9
	.long	.LASF35
	.byte	0x1
	.byte	0x4d
	.long	.LASF26
	.byte	0x1
	.long	0x15a
	.uleb128 0xa
	.long	.LASF23
	.byte	0x1
	.byte	0x4d
	.long	0x5b
	.uleb128 0xa
	.long	.LASF24
	.byte	0x1
	.byte	0x4d
	.long	0x7f
	.uleb128 0xa
	.long	.LASF19
	.byte	0x1
	.byte	0x4d
	.long	0x6d
	.uleb128 0xa
	.long	.LASF25
	.byte	0x1
	.byte	0x4d
	.long	0x5b
	.byte	0
	.uleb128 0xb
	.long	.LASF36
	.byte	0x1
	.byte	0x14
	.long	.LASF37
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0xa3d
	.uleb128 0xc
	.long	0x11d
	.long	.LBB102
	.long	.Ldebug_ranges0+0
	.byte	0x1
	.byte	0x19
	.long	0x1a7
	.uleb128 0xd
	.long	0x14e
	.long	.LLST0
	.uleb128 0xd
	.long	0x143
	.long	.LLST1
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST2
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB106
	.long	.Ldebug_ranges0+0x20
	.byte	0x1
	.byte	0x1a
	.long	0x1db
	.uleb128 0xd
	.long	0x14e
	.long	.LLST3
	.uleb128 0xd
	.long	0x143
	.long	.LLST4
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST5
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB111
	.long	.Ldebug_ranges0+0x48
	.byte	0x1
	.byte	0x18
	.long	0x20f
	.uleb128 0xd
	.long	0x14e
	.long	.LLST6
	.uleb128 0xd
	.long	0x143
	.long	.LLST7
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST8
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB123
	.long	.Ldebug_ranges0+0x70
	.byte	0x1
	.byte	0x1b
	.long	0x237
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB129
	.long	.Ldebug_ranges0+0x98
	.byte	0x1
	.byte	0x1c
	.long	0x25f
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB134
	.long	.Ldebug_ranges0+0xb8
	.byte	0x1
	.byte	0x1d
	.long	0x287
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB138
	.long	.Ldebug_ranges0+0xd0
	.byte	0x1
	.byte	0x1e
	.long	0x2af
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB142
	.long	.Ldebug_ranges0+0xe8
	.byte	0x1
	.byte	0x21
	.long	0x2e3
	.uleb128 0xd
	.long	0x14e
	.long	.LLST9
	.uleb128 0xd
	.long	0x143
	.long	.LLST10
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST11
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB148
	.long	.Ldebug_ranges0+0x110
	.byte	0x1
	.byte	0x22
	.long	0x30b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB157
	.long	.Ldebug_ranges0+0x140
	.byte	0x1
	.byte	0x1f
	.long	0x33f
	.uleb128 0xd
	.long	0x14e
	.long	.LLST12
	.uleb128 0xd
	.long	0x143
	.long	.LLST13
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST14
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB164
	.long	.Ldebug_ranges0+0x160
	.byte	0x1
	.byte	0x20
	.long	0x373
	.uleb128 0xd
	.long	0x14e
	.long	.LLST15
	.uleb128 0xd
	.long	0x143
	.long	.LLST16
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST16
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB172
	.long	.Ldebug_ranges0+0x178
	.byte	0x1
	.byte	0x23
	.long	0x39b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB178
	.long	.Ldebug_ranges0+0x1a0
	.byte	0x1
	.byte	0x24
	.long	0x3c3
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB182
	.long	.Ldebug_ranges0+0x1b8
	.byte	0x1
	.byte	0x25
	.long	0x3eb
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB186
	.long	.Ldebug_ranges0+0x1d0
	.byte	0x1
	.byte	0x26
	.long	0x413
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB190
	.long	.Ldebug_ranges0+0x1e8
	.byte	0x1
	.byte	0x29
	.long	0x447
	.uleb128 0xd
	.long	0x14e
	.long	.LLST18
	.uleb128 0xd
	.long	0x143
	.long	.LLST19
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST20
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB195
	.long	.Ldebug_ranges0+0x208
	.byte	0x1
	.byte	0x2a
	.long	0x47b
	.uleb128 0xd
	.long	0x14e
	.long	.LLST21
	.uleb128 0xd
	.long	0x143
	.long	.LLST22
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST23
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB203
	.long	.Ldebug_ranges0+0x230
	.byte	0x1
	.byte	0x27
	.long	0x4af
	.uleb128 0xd
	.long	0x14e
	.long	.LLST24
	.uleb128 0xd
	.long	0x143
	.long	.LLST25
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST26
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB207
	.long	.Ldebug_ranges0+0x248
	.byte	0x1
	.byte	0x28
	.long	0x4e3
	.uleb128 0xd
	.long	0x14e
	.long	.LLST27
	.uleb128 0xd
	.long	0x143
	.long	.LLST28
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST29
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB219
	.long	.Ldebug_ranges0+0x270
	.byte	0x1
	.byte	0x2b
	.long	0x50b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB225
	.long	.Ldebug_ranges0+0x298
	.byte	0x1
	.byte	0x2c
	.long	0x533
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB230
	.long	.Ldebug_ranges0+0x2b8
	.byte	0x1
	.byte	0x2d
	.long	0x55b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB234
	.long	.Ldebug_ranges0+0x2d0
	.byte	0x1
	.byte	0x2e
	.long	0x583
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB238
	.long	.Ldebug_ranges0+0x2e8
	.byte	0x1
	.byte	0x31
	.long	0x5b7
	.uleb128 0xd
	.long	0x14e
	.long	.LLST30
	.uleb128 0xd
	.long	0x143
	.long	.LLST31
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST32
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB243
	.long	.Ldebug_ranges0+0x308
	.byte	0x1
	.byte	0x32
	.long	0x5eb
	.uleb128 0xd
	.long	0x14e
	.long	.LLST33
	.uleb128 0xd
	.long	0x143
	.long	.LLST34
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST35
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB251
	.long	.Ldebug_ranges0+0x330
	.byte	0x1
	.byte	0x2f
	.long	0x61f
	.uleb128 0xd
	.long	0x14e
	.long	.LLST36
	.uleb128 0xd
	.long	0x143
	.long	.LLST37
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST38
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB255
	.long	.Ldebug_ranges0+0x348
	.byte	0x1
	.byte	0x30
	.long	0x653
	.uleb128 0xd
	.long	0x14e
	.long	.LLST39
	.uleb128 0xd
	.long	0x143
	.long	.LLST40
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST41
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB267
	.long	.Ldebug_ranges0+0x370
	.byte	0x1
	.byte	0x33
	.long	0x67b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB273
	.long	.Ldebug_ranges0+0x398
	.byte	0x1
	.byte	0x34
	.long	0x6a3
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB279
	.long	.Ldebug_ranges0+0x3c0
	.byte	0x1
	.byte	0x35
	.long	0x6cb
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB283
	.long	.Ldebug_ranges0+0x3d8
	.byte	0x1
	.byte	0x36
	.long	0x6f3
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB287
	.long	.Ldebug_ranges0+0x3f0
	.byte	0x1
	.byte	0x37
	.long	0x71b
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB291
	.long	.Ldebug_ranges0+0x408
	.byte	0x1
	.byte	0x39
	.long	0x74f
	.uleb128 0xd
	.long	0x14e
	.long	.LLST42
	.uleb128 0xd
	.long	0x143
	.long	.LLST43
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST44
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB296
	.long	.Ldebug_ranges0+0x428
	.byte	0x1
	.byte	0x3a
	.long	0x783
	.uleb128 0xd
	.long	0x14e
	.long	.LLST45
	.uleb128 0xd
	.long	0x143
	.long	.LLST46
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST47
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB305
	.long	.Ldebug_ranges0+0x450
	.byte	0x1
	.byte	0x38
	.long	0x7b7
	.uleb128 0xd
	.long	0x14e
	.long	.LLST48
	.uleb128 0xd
	.long	0x143
	.long	.LLST49
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST50
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB317
	.long	.Ldebug_ranges0+0x478
	.byte	0x1
	.byte	0x3b
	.long	0x7df
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB323
	.long	.Ldebug_ranges0+0x4a0
	.byte	0x1
	.byte	0x3c
	.long	0x807
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB329
	.long	.Ldebug_ranges0+0x4c8
	.byte	0x1
	.byte	0x3d
	.long	0x82f
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB333
	.long	.Ldebug_ranges0+0x4e0
	.byte	0x1
	.byte	0x3e
	.long	0x857
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB337
	.long	.Ldebug_ranges0+0x4f8
	.byte	0x1
	.byte	0x3f
	.long	0x87f
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB341
	.long	.Ldebug_ranges0+0x510
	.byte	0x1
	.byte	0x41
	.long	0x8b3
	.uleb128 0xd
	.long	0x14e
	.long	.LLST51
	.uleb128 0xd
	.long	0x143
	.long	.LLST52
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST53
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB348
	.long	.Ldebug_ranges0+0x540
	.byte	0x1
	.byte	0x42
	.long	0x8e7
	.uleb128 0xd
	.long	0x14e
	.long	.LLST54
	.uleb128 0xd
	.long	0x143
	.long	.LLST55
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST56
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB356
	.long	.Ldebug_ranges0+0x560
	.byte	0x1
	.byte	0x40
	.long	0x91b
	.uleb128 0xd
	.long	0x14e
	.long	.LLST57
	.uleb128 0xd
	.long	0x143
	.long	.LLST58
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST59
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB368
	.long	.Ldebug_ranges0+0x580
	.byte	0x1
	.byte	0x43
	.long	0x94f
	.uleb128 0xd
	.long	0x14e
	.long	.LLST60
	.uleb128 0xd
	.long	0x143
	.long	.LLST61
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST62
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB372
	.long	.Ldebug_ranges0+0x5a0
	.byte	0x1
	.byte	0x44
	.long	0x977
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB378
	.long	.Ldebug_ranges0+0x5c8
	.byte	0x1
	.byte	0x45
	.long	0x99f
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB382
	.long	.Ldebug_ranges0+0x5e0
	.byte	0x1
	.byte	0x46
	.long	0x9c7
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x11d
	.long	.LBB386
	.long	.Ldebug_ranges0+0x5f8
	.byte	0x1
	.byte	0x47
	.long	0x9ef
	.uleb128 0xe
	.long	0x14e
	.uleb128 0xe
	.long	0x143
	.uleb128 0xe
	.long	0x138
	.uleb128 0xe
	.long	0x12d
	.byte	0
	.uleb128 0xc
	.long	0x111
	.long	.LBB390
	.long	.Ldebug_ranges0+0x610
	.byte	0x1
	.byte	0x4b
	.long	0xa0c
	.uleb128 0xf
	.long	.LVL62
	.long	0xacf
	.byte	0
	.uleb128 0x10
	.long	0x11d
	.long	.LBB398
	.long	.Ldebug_ranges0+0x630
	.byte	0x1
	.byte	0x49
	.uleb128 0xd
	.long	0x14e
	.long	.LLST63
	.uleb128 0xd
	.long	0x143
	.long	.LLST64
	.uleb128 0xe
	.long	0x138
	.uleb128 0xd
	.long	0x12d
	.long	.LLST65
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	0x11d
	.long	.LASF26
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0xa75
	.uleb128 0x12
	.long	0x12d
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x12
	.long	0x138
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0x12
	.long	0x143
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0x12
	.long	0x14e
	.uleb128 0x2
	.byte	0x91
	.sleb128 12
	.byte	0
	.uleb128 0x11
	.long	0x111
	.long	.LASF27
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0xa96
	.uleb128 0xf
	.long	.LVL64
	.long	0xacf
	.byte	0
	.uleb128 0x13
	.long	.LASF16
	.byte	0x1
	.byte	0x11
	.long	0xbd
	.uleb128 0x5
	.byte	0x3
	.long	idt_ptr
	.uleb128 0x14
	.long	0xc8
	.long	0xab7
	.uleb128 0x15
	.long	0xab7
	.byte	0xff
	.byte	0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF28
	.uleb128 0x13
	.long	.LASF29
	.byte	0x1
	.byte	0x12
	.long	0xaa7
	.uleb128 0x5
	.byte	0x3
	.long	idt_entries
	.uleb128 0x16
	.long	.LASF38
	.long	.LASF38
	.byte	0x1
	.byte	0x13
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x3b
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x20
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x20
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x52
	.uleb128 0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x1d
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x52
	.uleb128 0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x58
	.uleb128 0xb
	.uleb128 0x59
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x5
	.byte	0
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LLST0:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST1:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST2:
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x2
	.byte	0x31
	.byte	0x9f
	.long	0
	.long	0
.LLST3:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST4:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST5:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x32
	.byte	0x9f
	.long	0
	.long	0
.LLST6:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST7:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST8:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.long	0
	.long	0
.LLST9:
	.long	.LVL12-.Ltext0
	.long	.LVL13-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST10:
	.long	.LVL12-.Ltext0
	.long	.LVL13-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST11:
	.long	.LVL12-.Ltext0
	.long	.LVL13-.Ltext0
	.value	0x2
	.byte	0x39
	.byte	0x9f
	.long	0
	.long	0
.LLST12:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST13:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST14:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x2
	.byte	0x37
	.byte	0x9f
	.long	0
	.long	0
.LLST15:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST16:
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST18:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST19:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST20:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x2
	.byte	0x41
	.byte	0x9f
	.long	0
	.long	0
.LLST21:
	.long	.LVL23-.Ltext0
	.long	.LVL24-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST22:
	.long	.LVL23-.Ltext0
	.long	.LVL24-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST23:
	.long	.LVL23-.Ltext0
	.long	.LVL24-.Ltext0
	.value	0x2
	.byte	0x42
	.byte	0x9f
	.long	0
	.long	0
.LLST24:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST25:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST26:
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x2
	.byte	0x3f
	.byte	0x9f
	.long	0
	.long	0
.LLST27:
	.long	.LVL20-.Ltext0
	.long	.LVL21-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST28:
	.long	.LVL20-.Ltext0
	.long	.LVL21-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST29:
	.long	.LVL20-.Ltext0
	.long	.LVL21-.Ltext0
	.value	0x2
	.byte	0x40
	.byte	0x9f
	.long	0
	.long	0
.LLST30:
	.long	.LVL31-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST31:
	.long	.LVL31-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST32:
	.long	.LVL31-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x2
	.byte	0x49
	.byte	0x9f
	.long	0
	.long	0
.LLST33:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST34:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST35:
	.long	.LVL33-.Ltext0
	.long	.LVL34-.Ltext0
	.value	0x2
	.byte	0x4a
	.byte	0x9f
	.long	0
	.long	0
.LLST36:
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST37:
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST38:
	.long	.LVL29-.Ltext0
	.long	.LVL30-.Ltext0
	.value	0x2
	.byte	0x47
	.byte	0x9f
	.long	0
	.long	0
.LLST39:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST40:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST41:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x2
	.byte	0x48
	.byte	0x9f
	.long	0
	.long	0
.LLST42:
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST43:
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST44:
	.long	.LVL41-.Ltext0
	.long	.LVL42-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x21
	.byte	0x9f
	.long	0
	.long	0
.LLST45:
	.long	.LVL43-.Ltext0
	.long	.LVL44-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST46:
	.long	.LVL43-.Ltext0
	.long	.LVL44-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST47:
	.long	.LVL43-.Ltext0
	.long	.LVL44-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x22
	.byte	0x9f
	.long	0
	.long	0
.LLST48:
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST49:
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST50:
	.long	.LVL40-.Ltext0
	.long	.LVL41-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x20
	.byte	0x9f
	.long	0
	.long	0
.LLST51:
	.long	.LVL51-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST52:
	.long	.LVL51-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST53:
	.long	.LVL51-.Ltext0
	.long	.LVL52-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x29
	.byte	0x9f
	.long	0
	.long	0
.LLST54:
	.long	.LVL52-.Ltext0
	.long	.LVL53-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST55:
	.long	.LVL52-.Ltext0
	.long	.LVL53-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST56:
	.long	.LVL52-.Ltext0
	.long	.LVL53-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x2a
	.byte	0x9f
	.long	0
	.long	0
.LLST57:
	.long	.LVL50-.Ltext0
	.long	.LVL51-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST58:
	.long	.LVL50-.Ltext0
	.long	.LVL51-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST59:
	.long	.LVL50-.Ltext0
	.long	.LVL51-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x28
	.byte	0x9f
	.long	0
	.long	0
.LLST60:
	.long	.LVL54-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST61:
	.long	.LVL54-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST62:
	.long	.LVL54-.Ltext0
	.long	.LVL55-.Ltext0
	.value	0x3
	.byte	0x8
	.byte	0x2b
	.byte	0x9f
	.long	0
	.long	0
.LLST63:
	.long	.LVL60-.Ltext0
	.long	.LVL61-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x8e
	.byte	0x9f
	.long	0
	.long	0
.LLST64:
	.long	.LVL60-.Ltext0
	.long	.LVL61-.Ltext0
	.value	0x2
	.byte	0x38
	.byte	0x9f
	.long	0
	.long	0
.LLST65:
	.long	.LVL60-.Ltext0
	.long	.LVL61-.Ltext0
	.value	0x3
	.byte	0x9
	.byte	0x80
	.byte	0x9f
	.long	0
	.long	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.value	0
	.value	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.long	.LBB102-.Ltext0
	.long	.LBE102-.Ltext0
	.long	.LBB116-.Ltext0
	.long	.LBE116-.Ltext0
	.long	.LBB121-.Ltext0
	.long	.LBE121-.Ltext0
	.long	0
	.long	0
	.long	.LBB106-.Ltext0
	.long	.LBE106-.Ltext0
	.long	.LBB118-.Ltext0
	.long	.LBE118-.Ltext0
	.long	.LBB122-.Ltext0
	.long	.LBE122-.Ltext0
	.long	.LBB128-.Ltext0
	.long	.LBE128-.Ltext0
	.long	0
	.long	0
	.long	.LBB111-.Ltext0
	.long	.LBE111-.Ltext0
	.long	.LBB117-.Ltext0
	.long	.LBE117-.Ltext0
	.long	.LBB119-.Ltext0
	.long	.LBE119-.Ltext0
	.long	.LBB120-.Ltext0
	.long	.LBE120-.Ltext0
	.long	0
	.long	0
	.long	.LBB123-.Ltext0
	.long	.LBE123-.Ltext0
	.long	.LBB133-.Ltext0
	.long	.LBE133-.Ltext0
	.long	.LBB137-.Ltext0
	.long	.LBE137-.Ltext0
	.long	.LBB141-.Ltext0
	.long	.LBE141-.Ltext0
	.long	0
	.long	0
	.long	.LBB129-.Ltext0
	.long	.LBE129-.Ltext0
	.long	.LBB147-.Ltext0
	.long	.LBE147-.Ltext0
	.long	.LBB154-.Ltext0
	.long	.LBE154-.Ltext0
	.long	0
	.long	0
	.long	.LBB134-.Ltext0
	.long	.LBE134-.Ltext0
	.long	.LBB155-.Ltext0
	.long	.LBE155-.Ltext0
	.long	0
	.long	0
	.long	.LBB138-.Ltext0
	.long	.LBE138-.Ltext0
	.long	.LBB156-.Ltext0
	.long	.LBE156-.Ltext0
	.long	0
	.long	0
	.long	.LBB142-.Ltext0
	.long	.LBE142-.Ltext0
	.long	.LBB161-.Ltext0
	.long	.LBE161-.Ltext0
	.long	.LBB169-.Ltext0
	.long	.LBE169-.Ltext0
	.long	.LBB171-.Ltext0
	.long	.LBE171-.Ltext0
	.long	0
	.long	0
	.long	.LBB148-.Ltext0
	.long	.LBE148-.Ltext0
	.long	.LBB163-.Ltext0
	.long	.LBE163-.Ltext0
	.long	.LBB170-.Ltext0
	.long	.LBE170-.Ltext0
	.long	.LBB177-.Ltext0
	.long	.LBE177-.Ltext0
	.long	.LBB181-.Ltext0
	.long	.LBE181-.Ltext0
	.long	0
	.long	0
	.long	.LBB157-.Ltext0
	.long	.LBE157-.Ltext0
	.long	.LBB162-.Ltext0
	.long	.LBE162-.Ltext0
	.long	.LBB167-.Ltext0
	.long	.LBE167-.Ltext0
	.long	0
	.long	0
	.long	.LBB164-.Ltext0
	.long	.LBE164-.Ltext0
	.long	.LBB168-.Ltext0
	.long	.LBE168-.Ltext0
	.long	0
	.long	0
	.long	.LBB172-.Ltext0
	.long	.LBE172-.Ltext0
	.long	.LBB185-.Ltext0
	.long	.LBE185-.Ltext0
	.long	.LBB189-.Ltext0
	.long	.LBE189-.Ltext0
	.long	.LBB194-.Ltext0
	.long	.LBE194-.Ltext0
	.long	0
	.long	0
	.long	.LBB178-.Ltext0
	.long	.LBE178-.Ltext0
	.long	.LBB200-.Ltext0
	.long	.LBE200-.Ltext0
	.long	0
	.long	0
	.long	.LBB182-.Ltext0
	.long	.LBE182-.Ltext0
	.long	.LBB201-.Ltext0
	.long	.LBE201-.Ltext0
	.long	0
	.long	0
	.long	.LBB186-.Ltext0
	.long	.LBE186-.Ltext0
	.long	.LBB202-.Ltext0
	.long	.LBE202-.Ltext0
	.long	0
	.long	0
	.long	.LBB190-.Ltext0
	.long	.LBE190-.Ltext0
	.long	.LBB206-.Ltext0
	.long	.LBE206-.Ltext0
	.long	.LBB217-.Ltext0
	.long	.LBE217-.Ltext0
	.long	0
	.long	0
	.long	.LBB195-.Ltext0
	.long	.LBE195-.Ltext0
	.long	.LBB212-.Ltext0
	.long	.LBE212-.Ltext0
	.long	.LBB218-.Ltext0
	.long	.LBE218-.Ltext0
	.long	.LBB224-.Ltext0
	.long	.LBE224-.Ltext0
	.long	0
	.long	0
	.long	.LBB203-.Ltext0
	.long	.LBE203-.Ltext0
	.long	.LBB214-.Ltext0
	.long	.LBE214-.Ltext0
	.long	0
	.long	0
	.long	.LBB207-.Ltext0
	.long	.LBE207-.Ltext0
	.long	.LBB213-.Ltext0
	.long	.LBE213-.Ltext0
	.long	.LBB215-.Ltext0
	.long	.LBE215-.Ltext0
	.long	.LBB216-.Ltext0
	.long	.LBE216-.Ltext0
	.long	0
	.long	0
	.long	.LBB219-.Ltext0
	.long	.LBE219-.Ltext0
	.long	.LBB229-.Ltext0
	.long	.LBE229-.Ltext0
	.long	.LBB233-.Ltext0
	.long	.LBE233-.Ltext0
	.long	.LBB237-.Ltext0
	.long	.LBE237-.Ltext0
	.long	0
	.long	0
	.long	.LBB225-.Ltext0
	.long	.LBE225-.Ltext0
	.long	.LBB242-.Ltext0
	.long	.LBE242-.Ltext0
	.long	.LBB248-.Ltext0
	.long	.LBE248-.Ltext0
	.long	0
	.long	0
	.long	.LBB230-.Ltext0
	.long	.LBE230-.Ltext0
	.long	.LBB249-.Ltext0
	.long	.LBE249-.Ltext0
	.long	0
	.long	0
	.long	.LBB234-.Ltext0
	.long	.LBE234-.Ltext0
	.long	.LBB250-.Ltext0
	.long	.LBE250-.Ltext0
	.long	0
	.long	0
	.long	.LBB238-.Ltext0
	.long	.LBE238-.Ltext0
	.long	.LBB260-.Ltext0
	.long	.LBE260-.Ltext0
	.long	.LBB265-.Ltext0
	.long	.LBE265-.Ltext0
	.long	0
	.long	0
	.long	.LBB243-.Ltext0
	.long	.LBE243-.Ltext0
	.long	.LBB262-.Ltext0
	.long	.LBE262-.Ltext0
	.long	.LBB266-.Ltext0
	.long	.LBE266-.Ltext0
	.long	.LBB272-.Ltext0
	.long	.LBE272-.Ltext0
	.long	0
	.long	0
	.long	.LBB251-.Ltext0
	.long	.LBE251-.Ltext0
	.long	.LBB254-.Ltext0
	.long	.LBE254-.Ltext0
	.long	0
	.long	0
	.long	.LBB255-.Ltext0
	.long	.LBE255-.Ltext0
	.long	.LBB261-.Ltext0
	.long	.LBE261-.Ltext0
	.long	.LBB263-.Ltext0
	.long	.LBE263-.Ltext0
	.long	.LBB264-.Ltext0
	.long	.LBE264-.Ltext0
	.long	0
	.long	0
	.long	.LBB267-.Ltext0
	.long	.LBE267-.Ltext0
	.long	.LBB278-.Ltext0
	.long	.LBE278-.Ltext0
	.long	.LBB282-.Ltext0
	.long	.LBE282-.Ltext0
	.long	.LBB286-.Ltext0
	.long	.LBE286-.Ltext0
	.long	0
	.long	0
	.long	.LBB273-.Ltext0
	.long	.LBE273-.Ltext0
	.long	.LBB290-.Ltext0
	.long	.LBE290-.Ltext0
	.long	.LBB295-.Ltext0
	.long	.LBE295-.Ltext0
	.long	.LBB301-.Ltext0
	.long	.LBE301-.Ltext0
	.long	0
	.long	0
	.long	.LBB279-.Ltext0
	.long	.LBE279-.Ltext0
	.long	.LBB302-.Ltext0
	.long	.LBE302-.Ltext0
	.long	0
	.long	0
	.long	.LBB283-.Ltext0
	.long	.LBE283-.Ltext0
	.long	.LBB303-.Ltext0
	.long	.LBE303-.Ltext0
	.long	0
	.long	0
	.long	.LBB287-.Ltext0
	.long	.LBE287-.Ltext0
	.long	.LBB304-.Ltext0
	.long	.LBE304-.Ltext0
	.long	0
	.long	0
	.long	.LBB291-.Ltext0
	.long	.LBE291-.Ltext0
	.long	.LBB310-.Ltext0
	.long	.LBE310-.Ltext0
	.long	.LBB315-.Ltext0
	.long	.LBE315-.Ltext0
	.long	0
	.long	0
	.long	.LBB296-.Ltext0
	.long	.LBE296-.Ltext0
	.long	.LBB312-.Ltext0
	.long	.LBE312-.Ltext0
	.long	.LBB316-.Ltext0
	.long	.LBE316-.Ltext0
	.long	.LBB322-.Ltext0
	.long	.LBE322-.Ltext0
	.long	0
	.long	0
	.long	.LBB305-.Ltext0
	.long	.LBE305-.Ltext0
	.long	.LBB311-.Ltext0
	.long	.LBE311-.Ltext0
	.long	.LBB313-.Ltext0
	.long	.LBE313-.Ltext0
	.long	.LBB314-.Ltext0
	.long	.LBE314-.Ltext0
	.long	0
	.long	0
	.long	.LBB317-.Ltext0
	.long	.LBE317-.Ltext0
	.long	.LBB328-.Ltext0
	.long	.LBE328-.Ltext0
	.long	.LBB332-.Ltext0
	.long	.LBE332-.Ltext0
	.long	.LBB336-.Ltext0
	.long	.LBE336-.Ltext0
	.long	0
	.long	0
	.long	.LBB323-.Ltext0
	.long	.LBE323-.Ltext0
	.long	.LBB340-.Ltext0
	.long	.LBE340-.Ltext0
	.long	.LBB347-.Ltext0
	.long	.LBE347-.Ltext0
	.long	.LBB352-.Ltext0
	.long	.LBE352-.Ltext0
	.long	0
	.long	0
	.long	.LBB329-.Ltext0
	.long	.LBE329-.Ltext0
	.long	.LBB353-.Ltext0
	.long	.LBE353-.Ltext0
	.long	0
	.long	0
	.long	.LBB333-.Ltext0
	.long	.LBE333-.Ltext0
	.long	.LBB354-.Ltext0
	.long	.LBE354-.Ltext0
	.long	0
	.long	0
	.long	.LBB337-.Ltext0
	.long	.LBE337-.Ltext0
	.long	.LBB355-.Ltext0
	.long	.LBE355-.Ltext0
	.long	0
	.long	0
	.long	.LBB341-.Ltext0
	.long	.LBE341-.Ltext0
	.long	.LBB360-.Ltext0
	.long	.LBE360-.Ltext0
	.long	.LBB363-.Ltext0
	.long	.LBE363-.Ltext0
	.long	.LBB365-.Ltext0
	.long	.LBE365-.Ltext0
	.long	.LBB366-.Ltext0
	.long	.LBE366-.Ltext0
	.long	0
	.long	0
	.long	.LBB348-.Ltext0
	.long	.LBE348-.Ltext0
	.long	.LBB362-.Ltext0
	.long	.LBE362-.Ltext0
	.long	.LBB367-.Ltext0
	.long	.LBE367-.Ltext0
	.long	0
	.long	0
	.long	.LBB356-.Ltext0
	.long	.LBE356-.Ltext0
	.long	.LBB361-.Ltext0
	.long	.LBE361-.Ltext0
	.long	.LBB364-.Ltext0
	.long	.LBE364-.Ltext0
	.long	0
	.long	0
	.long	.LBB368-.Ltext0
	.long	.LBE368-.Ltext0
	.long	.LBB377-.Ltext0
	.long	.LBE377-.Ltext0
	.long	.LBB381-.Ltext0
	.long	.LBE381-.Ltext0
	.long	0
	.long	0
	.long	.LBB372-.Ltext0
	.long	.LBE372-.Ltext0
	.long	.LBB385-.Ltext0
	.long	.LBE385-.Ltext0
	.long	.LBB389-.Ltext0
	.long	.LBE389-.Ltext0
	.long	.LBB394-.Ltext0
	.long	.LBE394-.Ltext0
	.long	0
	.long	0
	.long	.LBB378-.Ltext0
	.long	.LBE378-.Ltext0
	.long	.LBB395-.Ltext0
	.long	.LBE395-.Ltext0
	.long	0
	.long	0
	.long	.LBB382-.Ltext0
	.long	.LBE382-.Ltext0
	.long	.LBB396-.Ltext0
	.long	.LBE396-.Ltext0
	.long	0
	.long	0
	.long	.LBB386-.Ltext0
	.long	.LBE386-.Ltext0
	.long	.LBB397-.Ltext0
	.long	.LBE397-.Ltext0
	.long	0
	.long	0
	.long	.LBB390-.Ltext0
	.long	.LBE390-.Ltext0
	.long	.LBB401-.Ltext0
	.long	.LBE401-.Ltext0
	.long	.LBB403-.Ltext0
	.long	.LBE403-.Ltext0
	.long	0
	.long	0
	.long	.LBB398-.Ltext0
	.long	.LBE398-.Ltext0
	.long	.LBB402-.Ltext0
	.long	.LBE402-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF35:
	.string	"idt_create_descriptor"
.LASF26:
	.string	"_Z21idt_create_descriptorhmth"
.LASF24:
	.string	"offset"
.LASF36:
	.string	"init_idt"
.LASF22:
	.string	"offset_high"
.LASF27:
	.string	"_Z8load_idtv"
.LASF34:
	.string	"load_idt"
.LASF33:
	.string	"decltype(nullptr)"
.LASF23:
	.string	"entry"
.LASF19:
	.string	"selector"
.LASF30:
	.string	"GNU C++11 5.3.0 -mtune=generic -march=pentiumpro -g -O2 -std=c++11 -ffreestanding -fbuiltin -fstack-protector-strong -fno-exceptions -fno-rtti"
.LASF31:
	.string	"arch/i386/idt.cpp"
.LASF6:
	.string	"unsigned char"
.LASF15:
	.string	"idt_ptr_t"
.LASF1:
	.string	"long unsigned int"
.LASF9:
	.string	"short unsigned int"
.LASF16:
	.string	"idt_ptr"
.LASF29:
	.string	"idt_entries"
.LASF32:
	.string	"/home/pfalcato/Spartix/kernel"
.LASF14:
	.string	"base"
.LASF12:
	.string	"unsigned int"
.LASF25:
	.string	"flags"
.LASF11:
	.string	"long long unsigned int"
.LASF7:
	.string	"uint8_t"
.LASF13:
	.string	"limit"
.LASF38:
	.string	"IDT_Flush"
.LASF21:
	.string	"type_attr"
.LASF18:
	.string	"offset_low"
.LASF28:
	.string	"sizetype"
.LASF2:
	.string	"long long int"
.LASF20:
	.string	"zero"
.LASF5:
	.string	"short int"
.LASF37:
	.string	"_Z8init_idtv"
.LASF8:
	.string	"uint16_t"
.LASF10:
	.string	"uint32_t"
.LASF0:
	.string	"long int"
.LASF3:
	.string	"long double"
.LASF4:
	.string	"signed char"
.LASF17:
	.string	"IDT_entry"
	.ident	"GCC: (GNU) 5.3.0"
