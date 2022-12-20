import algosdk from "algosdk";
import * as bkr from "beaker-ts";
export class VerificationKey {
    alpha1: Uint8Array[] = undefined;
    beta2: Uint8Array[][] = undefined;
    gamma2: Uint8Array[][] = undefined;
    delta2: Uint8Array[][] = undefined;
    IC: Uint8Array[][] = undefined;
    static codec: algosdk.ABIType = algosdk.ABIType.from("(byte[32][2],byte[32][2][2],byte[32][2][2],byte[32][2][2],byte[32][2][2])");
    static fields: string[] = ["alpha1", "beta2", "gamma2", "delta2", "IC"];
    static decodeResult(val: algosdk.ABIValue | undefined): VerificationKey {
        return bkr.decodeNamedTuple(val, VerificationKey.fields) as VerificationKey;
    }
    static decodeBytes(val: Uint8Array): VerificationKey {
        return bkr.decodeNamedTuple(VerificationKey.codec.decode(val), VerificationKey.fields) as VerificationKey;
    }
}
export class Proof {
    A: Uint8Array[] = undefined;
    B: Uint8Array[][] = undefined;
    C: Uint8Array[] = undefined;
    static codec: algosdk.ABIType = algosdk.ABIType.from("(byte[32][2],byte[32][2][2],byte[32][2])");
    static fields: string[] = ["A", "B", "C"];
    static decodeResult(val: algosdk.ABIValue | undefined): Proof {
        return bkr.decodeNamedTuple(val, Proof.fields) as Proof;
    }
    static decodeBytes(val: Uint8Array): Proof {
        return bkr.decodeNamedTuple(Proof.codec.decode(val), Proof.fields) as Proof;
    }
}
export class Verifier extends bkr.ApplicationClient {
    desc: string = "";
    override appSchema: bkr.Schema = { declared: {}, reserved: {} };
    override acctSchema: bkr.Schema = { declared: {}, reserved: {} };
    override approvalProgram: string = "I3ByYWdtYSB2ZXJzaW9uIDgKaW50Y2Jsb2NrIDAgMSA2NCAzMiA0NDgKYnl0ZWNibG9jayAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcgMHg3NjZiIDB4MTUxZjdjNzUgMHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCAweDA2ODEwMQp0eG4gTnVtQXBwQXJncwppbnRjXzAgLy8gMAo9PQpibnogbWFpbl9sOAp0eG5hIEFwcGxpY2F0aW9uQXJncyAwCnB1c2hieXRlcyAweDc5M2FlNDRkIC8vICJib290c3RyYXAoKGJ5dGVbMzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdKSl2b2lkIgo9PQpibnogbWFpbl9sNwp0eG5hIEFwcGxpY2F0aW9uQXJncyAwCnB1c2hieXRlcyAweDhiNzM3MWRhIC8vICJ2ZXJpZnkoYnl0ZVszMl1bXSwoYnl0ZVszMl1bMl0sYnl0ZVszMl1bMl1bMl0sYnl0ZVszMl1bMl0pKWJvb2wiCj09CmJueiBtYWluX2w2CnR4bmEgQXBwbGljYXRpb25BcmdzIDAKcHVzaGJ5dGVzIDB4NTljM2IwYTcgLy8gImdldF92aygpKGJ5dGVbMzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdLGJ5dGVbMzJdWzJdWzJdKSIKPT0KYm56IG1haW5fbDUKZXJyCm1haW5fbDU6CnR4biBPbkNvbXBsZXRpb24KaW50Y18wIC8vIE5vT3AKPT0KdHhuIEFwcGxpY2F0aW9uSUQKaW50Y18wIC8vIDAKIT0KJiYKYXNzZXJ0CmNhbGxzdWIgZ2V0dmtfMTMKc3RvcmUgMTAKYnl0ZWNfMiAvLyAweDE1MWY3Yzc1CmxvYWQgMTAKY29uY2F0CmxvZwppbnRjXzEgLy8gMQpyZXR1cm4KbWFpbl9sNjoKdHhuIE9uQ29tcGxldGlvbgppbnRjXzAgLy8gTm9PcAo9PQp0eG4gQXBwbGljYXRpb25JRAppbnRjXzAgLy8gMAohPQomJgphc3NlcnQKdHhuYSBBcHBsaWNhdGlvbkFyZ3MgMQpzdG9yZSAwCnR4bmEgQXBwbGljYXRpb25BcmdzIDIKc3RvcmUgMQpsb2FkIDAKbG9hZCAxCmNhbGxzdWIgdmVyaWZ5XzEyCnN0b3JlIDIKYnl0ZWNfMiAvLyAweDE1MWY3Yzc1CnB1c2hieXRlcyAweDAwIC8vIDB4MDAKaW50Y18wIC8vIDAKbG9hZCAyCnNldGJpdApjb25jYXQKbG9nCmludGNfMSAvLyAxCnJldHVybgptYWluX2w3Ogp0eG4gT25Db21wbGV0aW9uCmludGNfMCAvLyBOb09wCj09CnR4biBBcHBsaWNhdGlvbklECmludGNfMCAvLyAwCiE9CiYmCmFzc2VydAp0eG5hIEFwcGxpY2F0aW9uQXJncyAxCmNhbGxzdWIgYm9vdHN0cmFwXzExCmludGNfMSAvLyAxCnJldHVybgptYWluX2w4Ogp0eG4gT25Db21wbGV0aW9uCmludGNfMCAvLyBOb09wCj09CmJueiBtYWluX2wxMAplcnIKbWFpbl9sMTA6CnR4biBBcHBsaWNhdGlvbklECmludGNfMCAvLyAwCj09CmFzc2VydApjYWxsc3ViIGNyZWF0ZV8wCmludGNfMSAvLyAxCnJldHVybgoKLy8gY3JlYXRlCmNyZWF0ZV8wOgppbnRjXzEgLy8gMQpyZXR1cm4KCi8vIGFkZAphZGRfMToKY2FsbHN1YiBjdXJ2ZWFkZF83CnJldHN1YgoKLy8gc2NhbGUKc2NhbGVfMjoKY2FsbHN1YiBjdXJ2ZXNjYWxhcm11bF84CnJldHN1YgoKLy8gbmVnYXRlCm5lZ2F0ZV8zOgpzdG9yZSAzNwpsb2FkIDM3CmJ5dGVjXzMgLy8gMHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMApiPT0KYm56IG5lZ2F0ZV8zX2wyCmxvYWQgMzcKYnl0ZWNfMCAvLyAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcKbG9hZCAzNwpleHRyYWN0IDMyIDAKYnl0ZWNfMCAvLyAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcKYiUKYi0KcmVwbGFjZTIgMzIKYiBuZWdhdGVfM19sMwpuZWdhdGVfM19sMjoKbG9hZCAzNwpuZWdhdGVfM19sMzoKcmV0c3ViCgovLyBhc3NlcnRfcHJvb2ZfcG9pbnRzX2x0X3ByaW1lX3EKYXNzZXJ0cHJvb2Zwb2ludHNsdHByaW1lcV80OgpzdG9yZSAxNApsb2FkIDE0CmV4dHJhY3QgMCA2NApzdG9yZSAxNQpsb2FkIDE1CmV4dHJhY3QgMCAzMgpieXRlY18wIC8vIDB4MzA2NDRlNzJlMTMxYTAyOWI4NTA0NWI2ODE4MTU4NWQ5NzgxNmE5MTY4NzFjYThkM2MyMDhjMTZkODdjZmQ0NwpiPAovLyBhIHBvaW50ID4gcHJpbWVxCmFzc2VydApsb2FkIDE1CmV4dHJhY3QgMzIgMApieXRlY18wIC8vIDB4MzA2NDRlNzJlMTMxYTAyOWI4NTA0NWI2ODE4MTU4NWQ5NzgxNmE5MTY4NzFjYThkM2MyMDhjMTZkODdjZmQ0NwpiPAovLyBhIHBvaW50ID4gcHJpbWVxCmFzc2VydApsb2FkIDE0CmV4dHJhY3QgNjQgMTI4CnN0b3JlIDE2CmxvYWQgMTYKaW50Y18yIC8vIDY0CmludGNfMCAvLyAwCioKaW50Y18yIC8vIDY0CmV4dHJhY3QzCnN0b3JlIDE3CmxvYWQgMTcKZXh0cmFjdCAwIDMyCmJ5dGVjXzAgLy8gMHgzMDY0NGU3MmUxMzFhMDI5Yjg1MDQ1YjY4MTgxNTg1ZDk3ODE2YTkxNjg3MWNhOGQzYzIwOGMxNmQ4N2NmZDQ3CmI8Ci8vIGIwIHBvaW50ID4gcHJpbWVxCmFzc2VydApsb2FkIDE3CmV4dHJhY3QgMzIgMApieXRlY18wIC8vIDB4MzA2NDRlNzJlMTMxYTAyOWI4NTA0NWI2ODE4MTU4NWQ5NzgxNmE5MTY4NzFjYThkM2MyMDhjMTZkODdjZmQ0NwpiPAovLyBiMCBwb2ludCA+IHByaW1lcQphc3NlcnQKbG9hZCAxNgppbnRjXzIgLy8gNjQKaW50Y18xIC8vIDEKKgppbnRjXzIgLy8gNjQKZXh0cmFjdDMKc3RvcmUgMTgKbG9hZCAxOApleHRyYWN0IDAgMzIKYnl0ZWNfMCAvLyAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcKYjwKLy8gYjEgcG9pbnQgPiBwcmltZXEKYXNzZXJ0CmxvYWQgMTgKZXh0cmFjdCAzMiAwCmJ5dGVjXzAgLy8gMHgzMDY0NGU3MmUxMzFhMDI5Yjg1MDQ1YjY4MTgxNTg1ZDk3ODE2YTkxNjg3MWNhOGQzYzIwOGMxNmQ4N2NmZDQ3CmI8Ci8vIGIxIHBvaW50ID4gcHJpbWVxCmFzc2VydApsb2FkIDE0CmV4dHJhY3QgMTkyIDAKc3RvcmUgMTkKbG9hZCAxOQpleHRyYWN0IDAgMzIKYnl0ZWNfMCAvLyAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcKYjwKLy8gYyBwb2ludCA+IHByaW1lcQphc3NlcnQKbG9hZCAxOQpleHRyYWN0IDMyIDAKYnl0ZWNfMCAvLyAweDMwNjQ0ZTcyZTEzMWEwMjliODUwNDViNjgxODE1ODVkOTc4MTZhOTE2ODcxY2E4ZDNjMjA4YzE2ZDg3Y2ZkNDcKYjwKLy8gYyBwb2ludCA+IHByaW1lcQphc3NlcnQKcmV0c3ViCgovLyBjb21wdXRlX2xpbmVhcl9jb21iaW5hdGlvbgpjb21wdXRlbGluZWFyY29tYmluYXRpb25fNToKc3RvcmUgMjEKc3RvcmUgMjAKYnl0ZWNfMyAvLyAweDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwCnN0b3JlIDIzCmludGNfMCAvLyAwCnN0b3JlIDI0CmNvbXB1dGVsaW5lYXJjb21iaW5hdGlvbl81X2wxOgpsb2FkIDI0CmxvYWQgMjEKaW50Y18wIC8vIDAKZXh0cmFjdF91aW50MTYKPApieiBjb21wdXRlbGluZWFyY29tYmluYXRpb25fNV9sMwpsb2FkIDIxCmludGNfMyAvLyAzMgpsb2FkIDI0CioKcHVzaGludCAyIC8vIDIKKwppbnRjXzMgLy8gMzIKZXh0cmFjdDMKc3RvcmUgMjUKbG9hZCAyNQpwdXNoYnl0ZXMgMHgzMDY0NGU3MmUxMzFhMDI5Yjg1MDQ1YjY4MTgxNTg1ZDI4MzNlODQ4NzliOTcwOTE0M2UxZjU5M2YwMDAwMDAxIC8vIDB4MzA2NDRlNzJlMTMxYTAyOWI4NTA0NWI2ODE4MTU4NWQyODMzZTg0ODc5Yjk3MDkxNDNlMWY1OTNmMDAwMDAwMQpiPAovLyB2ZXJpZmllciBndGUgc25hcmsgc2NhbGFyCmFzc2VydApsb2FkIDIwCmludGMgNCAvLyA0NDgKZGlnIDEKbGVuCnN1YnN0cmluZzMKaW50Y18yIC8vIDY0CmxvYWQgMjQKaW50Y18xIC8vIDEKKwoqCmludGNfMiAvLyA2NApleHRyYWN0Mwpsb2FkIDI1CmNhbGxzdWIgc2NhbGVfMgpzdG9yZSAyMgpsb2FkIDIzCmxvYWQgMjIKY2FsbHN1YiBhZGRfMQpzdG9yZSAyMwpsb2FkIDI0CmludGNfMSAvLyAxCisKc3RvcmUgMjQKYiBjb21wdXRlbGluZWFyY29tYmluYXRpb25fNV9sMQpjb21wdXRlbGluZWFyY29tYmluYXRpb25fNV9sMzoKbG9hZCAyMAppbnRjIDQgLy8gNDQ4CmRpZyAxCmxlbgpzdWJzdHJpbmczCmludGNfMiAvLyA2NAppbnRjXzAgLy8gMAoqCmludGNfMiAvLyA2NApleHRyYWN0MwpzdG9yZSAyNgpsb2FkIDIzCmxvYWQgMjYKY2FsbHN1YiBhZGRfMQpzdG9yZSAyMwpsb2FkIDIzCnJldHN1YgoKLy8gdmFsaWRfcGFpcmluZwp2YWxpZHBhaXJpbmdfNjoKc3RvcmUgMjkKc3RvcmUgMjgKc3RvcmUgMjcKbG9hZCAyNwpleHRyYWN0IDAgNjQKY2FsbHN1YiBuZWdhdGVfMwpzdG9yZSAzMApsb2FkIDI4CmV4dHJhY3QgMCA2NApzdG9yZSAzMgpsb2FkIDMwCmxvYWQgMzIKY29uY2F0CnN0b3JlIDMwCmxvYWQgMzAKbG9hZCAyOQpjb25jYXQKc3RvcmUgMzAKbG9hZCAyNwpleHRyYWN0IDE5MiAwCnN0b3JlIDMzCmxvYWQgMzAKbG9hZCAzMwpjb25jYXQKc3RvcmUgMzAKbG9hZCAyNwpleHRyYWN0IDY0IDEyOApzdG9yZSAzMQpsb2FkIDI4CmV4dHJhY3QgNjQgMTI4CnN0b3JlIDM0CmxvYWQgMzEKbG9hZCAzNApjb25jYXQKc3RvcmUgMzEKbG9hZCAyOApleHRyYWN0IDE5MiAxMjgKc3RvcmUgMzUKbG9hZCAzMQpsb2FkIDM1CmNvbmNhdApzdG9yZSAzMQpsb2FkIDI4CnB1c2hpbnQgMzIwIC8vIDMyMApwdXNoaW50IDEyOCAvLyAxMjgKZXh0cmFjdDMKc3RvcmUgMzYKbG9hZCAzMQpsb2FkIDM2CmNvbmNhdApzdG9yZSAzMQpsb2FkIDMwCmxvYWQgMzEKY2FsbHN1YiBjdXJ2ZXBhaXJpbmdfOQpyZXRzdWIKCi8vIGN1cnZlX2FkZApjdXJ2ZWFkZF83OgplY19hZGQgQk4yNTRfRzEKcmV0c3ViCgovLyBjdXJ2ZV9zY2FsYXJfbXVsCmN1cnZlc2NhbGFybXVsXzg6CmVjX3NjYWxhcl9tdWwgQk4yNTRfRzEKcmV0c3ViCgovLyBjdXJ2ZV9wYWlyaW5nCmN1cnZlcGFpcmluZ185OgplY19wYWlyaW5nX2NoZWNrIEJOMjU0CnJldHN1YgoKLy8gYXV0aF9vbmx5CmF1dGhvbmx5XzEwOgpnbG9iYWwgQ3JlYXRvckFkZHJlc3MKPT0KcmV0c3ViCgovLyBib290c3RyYXAKYm9vdHN0cmFwXzExOgpzdG9yZSAxMwp0eG4gU2VuZGVyCmNhbGxzdWIgYXV0aG9ubHlfMTAKLy8gdW5hdXRob3JpemVkCmFzc2VydApieXRlY18xIC8vICJ2ayIKbG9hZCAxMwpib3hfcHV0CnJldHN1YgoKLy8gdmVyaWZ5CnZlcmlmeV8xMjoKc3RvcmUgNApzdG9yZSAzCnB1c2hpbnQgMTYwMDAwIC8vIDE2MDAwMApwdXNoaW50IDEwIC8vIDEwCisKc3RvcmUgNQp2ZXJpZnlfMTJfbDE6CmxvYWQgNQpnbG9iYWwgT3Bjb2RlQnVkZ2V0Cj4KYnogdmVyaWZ5XzEyX2wzCml0eG5fYmVnaW4KcHVzaGludCA2IC8vIGFwcGwKaXR4bl9maWVsZCBUeXBlRW51bQpwdXNoaW50IDUgLy8gRGVsZXRlQXBwbGljYXRpb24KaXR4bl9maWVsZCBPbkNvbXBsZXRpb24KYnl0ZWMgNCAvLyAweDA2ODEwMQppdHhuX2ZpZWxkIEFwcHJvdmFsUHJvZ3JhbQpieXRlYyA0IC8vIDB4MDY4MTAxCml0eG5fZmllbGQgQ2xlYXJTdGF0ZVByb2dyYW0KaXR4bl9zdWJtaXQKYiB2ZXJpZnlfMTJfbDEKdmVyaWZ5XzEyX2wzOgpsb2FkIDQKY2FsbHN1YiBhc3NlcnRwcm9vZnBvaW50c2x0cHJpbWVxXzQKYnl0ZWNfMSAvLyAidmsiCmJveF9nZXQKc3RvcmUgOApzdG9yZSA3CmxvYWQgOAovLyBWZXJpZmljYXRpb24gS2V5IG5vdCBzZXQKYXNzZXJ0CmxvYWQgNwpzdG9yZSA2CmxvYWQgNgpsb2FkIDMKY2FsbHN1YiBjb21wdXRlbGluZWFyY29tYmluYXRpb25fNQpzdG9yZSA5CmxvYWQgNApsb2FkIDYKbG9hZCA5CmNhbGxzdWIgdmFsaWRwYWlyaW5nXzYKIQohCnJldHN1YgoKLy8gZ2V0X3ZrCmdldHZrXzEzOgpieXRlY18xIC8vICJ2ayIKYm94X2dldApzdG9yZSAxMgpzdG9yZSAxMQpsb2FkIDEyCi8vIFZlcmlmaWNhdGlvbiBLZXkgbm90IHNldAphc3NlcnQKbG9hZCAxMQpyZXRzdWI=";
    override clearProgram: string = "I3ByYWdtYSB2ZXJzaW9uIDgKcHVzaGludCAwIC8vIDAKcmV0dXJu";
    override methods: algosdk.ABIMethod[] = [
        new algosdk.ABIMethod({ name: "bootstrap", desc: "", args: [{ type: "(byte[32][2],byte[32][2][2],byte[32][2][2],byte[32][2][2],byte[32][2][2])", name: "vk", desc: "" }], returns: { type: "void", desc: "" } }),
        new algosdk.ABIMethod({ name: "verify", desc: "", args: [{ type: "byte[32][]", name: "inputs", desc: "" }, { type: "(byte[32][2],byte[32][2][2],byte[32][2])", name: "proof", desc: "" }], returns: { type: "bool", desc: "" } }),
        new algosdk.ABIMethod({ name: "get_vk", desc: "", args: [], returns: { type: "(byte[32][2],byte[32][2][2],byte[32][2][2],byte[32][2][2],byte[32][2][2])", desc: "" } })
    ];
    async bootstrap(args: {
        vk: VerificationKey;
    }, txnParams?: bkr.TransactionOverrides): Promise<bkr.ABIResult<void>> {
        const result = await this.execute(await this.compose.bootstrap({ vk: args.vk }, txnParams));
        return new bkr.ABIResult<void>(result);
    }
    async verify(args: {
        inputs: Uint8Array[];
        proof: Proof;
    }, txnParams?: bkr.TransactionOverrides): Promise<bkr.ABIResult<boolean>> {
        const result = await this.execute(await this.compose.verify({ inputs: args.inputs, proof: args.proof }, txnParams));
        return new bkr.ABIResult<boolean>(result, result.returnValue as boolean);
    }
    async get_vk(txnParams?: bkr.TransactionOverrides): Promise<bkr.ABIResult<[
        Uint8Array[],
        Uint8Array[][],
        Uint8Array[][],
        Uint8Array[][],
        Uint8Array[][]
    ]>> {
        const result = await this.execute(await this.compose.get_vk(txnParams));
        return new bkr.ABIResult<[
            Uint8Array[],
            Uint8Array[][],
            Uint8Array[][],
            Uint8Array[][],
            Uint8Array[][]
        ]>(result, result.returnValue as [
            Uint8Array[],
            Uint8Array[][],
            Uint8Array[][],
            Uint8Array[][],
            Uint8Array[][]
        ]);
    }
    compose = {
        bootstrap: async (args: {
            vk: VerificationKey;
        }, txnParams?: bkr.TransactionOverrides, atc?: algosdk.AtomicTransactionComposer): Promise<algosdk.AtomicTransactionComposer> => {
            return this.addMethodCall(algosdk.getMethodByName(this.methods, "bootstrap"), { vk: args.vk }, txnParams, atc);
        },
        verify: async (args: {
            inputs: Uint8Array[];
            proof: Proof;
        }, txnParams?: bkr.TransactionOverrides, atc?: algosdk.AtomicTransactionComposer): Promise<algosdk.AtomicTransactionComposer> => {
            return this.addMethodCall(algosdk.getMethodByName(this.methods, "verify"), { inputs: args.inputs, proof: args.proof }, txnParams, atc);
        },
        get_vk: async (txnParams?: bkr.TransactionOverrides, atc?: algosdk.AtomicTransactionComposer): Promise<algosdk.AtomicTransactionComposer> => {
            return this.addMethodCall(algosdk.getMethodByName(this.methods, "get_vk"), {}, txnParams, atc);
        }
    };
}
