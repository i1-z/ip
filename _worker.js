import { connect as 建立连接 } from 'cloudflare:sockets';

// 基础常量与编码字典（脱敏特征字面量）
const 字典 = {
    协议名: atob('dmxlc3M='),
    转换器: atob('U3ViQXBpLkNtbGlVc3NzUy5OZXQ='),
    规则配置: atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ=='),
    默认后缀: atob('LnByb3h5aXAuY21saXVzc3NzLm5ldA=='),
    兜底节点: atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='),
    测速域名: atob('c3BlZWQuY2xvdWRmbGFyZS5jb20='),
    默认标识: '3dfc81a7-8cba-4a83-b590-559860dd2a44',
    默认路径: '/?ed=2560',
    加密参数: atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ=='),
    明文参数: atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ=='),
    客户端标识: atob('djJyYXlOL2VkZ2V0dW5uZWw='),
    明文端口组: ['8080', '8880', '2052', '2082', '2086', '2095'],
    加密端口组: ['2053', '2083', '2087', '2096', '8443']
};

export default {
    async fetch(请求, 环境) {
        try {
            const 上下文 = await 初始化上下文(请求, 环境);
            if (!上下文.主标识) {
                return new Response('未检测到有效标识配置', { status: 404, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
            }

            const 升级头 = 请求.headers.get('Upgrade');
            if (升级头 && 升级头.toLowerCase() === 'websocket') {
                解析流参数(上下文);
                return 处理数据流(请求, 上下文);
            }

            return await 处理网页请求(请求, 环境, 上下文);
        } catch (异常) {
            return new Response(异常.toString(), { status: 500 });
        }
    }
};

async function 初始化上下文(请求, 环境) {
    const 网址 = new URL(请求.url);
    const 客户端信息 = 请求.headers.get('User-Agent') || 'null';
    let 主标识 = 环境.UUID || 环境.uuid || 环境.PASSWORD || 环境.pswd || 字典.默认标识;
    let 备用标识 = '';
    let 动态密钥 = 主标识;

    if (环境.KEY || 环境.TOKEN || (主标识 && !校验标识格式(主标识))) {
        动态密钥 = 环境.KEY || 环境.TOKEN || 主标识;
        const 周期天数 = Number(环境.TIME) || 30;
        const 更新时点 = Number(环境.UPTIME) || 3;
        const 标识组 = await 派生动态标识(动态密钥, 周期天数, 更新时点);
        主标识 = 标识组[0];
        备用标识 = 标识组[1];
    }

    const 零点时间戳 = Math.ceil(new Date().setHours(0, 0, 0, 0) / 1000);
    const 摘要值 = await 双重摘要(`${主标识}${零点时间戳}`);
    const 伪装标识 = `${摘要值.slice(0, 8)}-${摘要值.slice(8, 12)}-${摘要值.slice(12, 16)}-${摘要值.slice(16, 20)}-${摘要值.slice(20)}`;
    const 伪装主机 = `${摘要值.slice(6, 9)}.${摘要值.slice(13, 19)}`;

    const 中继列表 = 拆分列表(环境.PROXYIP || 环境.proxyip || '');
    const 随机中继 = 中继列表.length ? 中继列表[Math.floor(Math.random() * 中继列表.length)].toLowerCase() : (请求.cf?.colo || 'HKG') + 字典.默认后缀;

    const 代理列表 = 拆分列表(环境.HTTP || 环境.SOCKS5 || '');
    let 代理地址 = 代理列表.length ? 代理列表[Math.floor(Math.random() * 代理列表.length)] : '';
    const 启用网页代理 = 环境.HTTP ? true : 代理地址.toLowerCase().includes('http://');
    代理地址 = 代理地址.split('//')[1] || 代理地址;

    let 启用外部代理 = false;
    let 转换反代标记 = 环境.RPROXYIP || (!随机中继 ? 'true' : 'false');
    if (代理地址) {
        try {
            解析代理配置(代理地址);
            启用外部代理 = true;
            转换反代标记 = 环境.RPROXYIP || 'false';
        } catch {
            启用外部代理 = false;
        }
    }

    let 隧道路径 = 字典.默认路径;
    if (网址.searchParams.has('proxyip')) {
        隧道路径 = `/proxyip=${网址.searchParams.get('proxyip')}`;
        转换反代标记 = 'false';
    } else if (网址.searchParams.has('socks5') || 网址.searchParams.has('socks')) {
        const 参数值 = 网址.searchParams.get('socks5') || 网址.searchParams.get('socks');
        隧道路径 = `/?socks5=${参数值}${网址.searchParams.has('globalproxy') ? '&globalproxy' : ''}`;
        转换反代标记 = 'false';
    } else if (网址.searchParams.has('http')) {
        隧道路径 = `/?http=${网址.searchParams.get('http')}${网址.searchParams.has('globalproxy') ? '&globalproxy' : ''}`;
        转换反代标记 = 'false';
    }

    const 跳过证书 = 环境.SCV && 环境.SCV !== '0' && 环境.SCV !== 'false';

    return {
        网址,
        主机名: 请求.headers.get('Host') || 网址.hostname,
        客户端信息,
        客户端小写: 客户端信息.toLowerCase(),
        主标识,
        备用标识,
        动态密钥,
        伪装标识,
        伪装主机,
        中继节点: 随机中继,
        中继池: [],
        代理地址,
        启用网页代理,
        启用外部代理,
        转换反代标记,
        代理规则组: 环境.GO2SOCKS5 ? 拆分列表(环境.GO2SOCKS5) : ['*tapecontent.net', '*cloudatacdn.com', '*.loadshare.org'],
        拦截列表: 环境.BAN ? 拆分列表(环境.BAN) : [字典.测速域名],
        加密端口组: 环境.CFPORTS ? 拆分列表(环境.CFPORTS) : 字典.加密端口组,
        隧道路径,
        强制明文: 网址.searchParams.has('notls') ? 'true' : 'false',
        跳过证书,
        跳过证书参数: 跳过证书 ? '&allowInsecure=1' : '',
        配置名称: 环境.SUBNAME || '套餐服务',
        速度下限: Number(环境.DLS) || 8,
        备注偏移: Number(环境.CSVREMARK) || 1
    };
}

async function 处理网页请求(请求, 环境, 上下文) {
    const { 网址, 主标识, 动态密钥, 伪装标识, 主机名 } = 上下文;
    const 路径名 = 网址.pathname;
    const 路径小写 = 路径名.toLowerCase();

    if (路径小写 === '/') {
        if (环境.URL302) return Response.redirect(环境.URL302, 302);
        if (环境.URL) return await 反向代理网页(环境.URL, 网址);
        return new Response('<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Service is running.</h1></body></html>', {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
    }

    if (路径名 === `/${动态密钥}/edit` || 路径小写 === `/${主标识}/edit`) {
        return await 处理存储编辑(请求, 环境);
    }

    if (路径小写 === `/${伪装标识}`) {
        const 伪装内容 = await 构建订阅内容(环境, 上下文, true);
        return new Response(伪装内容, { status: 200 });
    }

    if (路径名 === `/${动态密钥}` || 路径小写 === `/${主标识}`) {
        const 订阅文本 = await 构建订阅内容(环境, 上下文, false);
        const 总额度 = 24 * 1099511627776;
        const 已用额度 = Math.floor(((Date.now() - new Date().setHours(0, 0, 0, 0)) / 86400000) * 总额度 / 2);
        const 响应头 = {
            'Profile-Update-Interval': '6',
            'Subscription-Userinfo': `upload=${已用额度}; download=${已用额度}; total=${总额度}; expire=4102329600`,
            'Cache-Control': 'no-store'
        };

        if (上下文.客户端小写.includes('mozilla') && !网址.search) {
            return new Response(渲染简易面板(上下文, 订阅文本), {
                status: 200,
                headers: { ...响应头, 'Content-Type': 'text/html;charset=utf-8' }
            });
        }

        return new Response(订阅文本, {
            status: 200,
            headers: {
                ...响应头,
                'Content-Disposition': `attachment; filename*=utf-8''${encodeURIComponent(上下文.配置名称)}`,
                'Content-Type': 'text/plain;charset=utf-8'
            }
        });
    }

    if (环境.URL302) return Response.redirect(环境.URL302, 302);
    if (环境.URL) return await 反向代理网页(环境.URL, 网址);
    return new Response('Not Found', { status: 404 });
}

async function 构建订阅内容(环境, 上下文, 是否伪装请求) {
    let 节点池 = 环境.ADD ? 拆分列表(环境.ADD) : [];
    let 接口池 = 环境.ADDAPI ? 拆分列表(环境.ADDAPI) : [];
    let 明文池 = 环境.ADDNOTLS ? 拆分列表(环境.ADDNOTLS) : [];
    let 明文接口池 = 环境.ADDNOTLSAPI ? 拆分列表(环境.ADDNOTLSAPI) : [];
    let 测速表池 = 环境.ADDCSV ? 拆分列表(环境.ADDCSV) : [];
    let 附加链接 = 环境.LINK ? 拆分列表(环境.LINK) : [];

    let 外部订阅器 = 网址参数或环境变量(上下文.网址, 环境);

    if (!外部订阅器 && 环境.KV) {
        const 存储内容 = await 环境.KV.get('ADD.txt');
        if (存储内容) {
            for (const 项 of 拆分列表(存储内容)) {
                if (项.startsWith('https://')) 接口池.push(项);
                else if (项.includes('://')) 附加链接.push(项);
                else 节点池.push(项);
            }
        }
    }

    if (节点池.length + 接口池.length + 明文池.length + 明文接口池.length + 测速表池.length === 0) {
        节点池.push('www.visa.com.sg:443#默认优选-SG', 'www.visa.com.hk:8443#默认优选-HK', 'icook.tw:2053#默认优选-TW');
    }

    const { 主机名, 伪装标识, 网址, 客户端小写 } = 上下文;
    let 伪装域名 = 上下文.伪装主机;
    let 动态明文列表 = [], 测速明文列表 = [];

    if (主机名.includes('.workers.dev') || 主机名.includes('notls') || 上下文.强制明文 === 'true') {
        上下文.强制明文 = 'true';
        伪装域名 = 主机名.includes('.workers.dev') ? `${伪装域名}.workers.dev` : `notls${伪装域名}.net`;
        动态明文列表 = await 拉取远程列表(明文接口池, 上下文);
        测速明文列表 = await 解析测速表格(测速表池, 'FALSE', 上下文);
    } else {
        伪装域名 = 主机名.includes('.pages.dev') ? `${伪装域名}.pages.dev` : `${伪装域名}.xyz`;
    }

    let 转换器地址 = 环境.SUBAPI || 字典.转换器;
    let 转换协议 = 'https';
    if (转换器地址.includes('http://')) {
        转换器地址 = 转换器地址.split('//')[1];
        转换协议 = 'http';
    } else {
        转换器地址 = 转换器地址.split('//')[1] || 转换器地址;
    }

    let 目标地址 = `${转换协议}://${外部订阅器}/sub?host=${伪装域名}&uuid=${伪装标识}&proxyip=${上下文.转换反代标记}&path=${encodeURIComponent(上下文.隧道路径)}`;
    let 采用编码 = true;

    if (!外部订阅器) {
        const 动态加密列表 = await 拉取远程列表(接口池, 上下文);
        const 测速加密列表 = await 解析测速表格(测速表池, 'TRUE', 上下文);
        节点池 = [...new Set([...节点池, ...动态加密列表, ...测速加密列表])];
        明文池 = [...new Set([...明文池, ...动态明文列表, ...测速明文列表])];
        目标地址 = `https://${主机名}/${伪装标识}${网址.search}`;
    }

    const 规则地址 = encodeURIComponent(环境.SUBCONFIG || 字典.规则配置);
    const 跳过验证 = 上下文.跳过证书 ? 'true' : 'false';

    if ((客户端小写.includes('clash') && !客户端小写.includes('nekobox')) || 网址.searchParams.has('clash')) {
        目标地址 = `${转换协议}://${转换器地址}/sub?target=clash&url=${encodeURIComponent(目标地址)}&config=${规则地址}&emoji=true&scv=${跳过验证}&new_name=true`;
        采用编码 = false;
    } else if (客户端小写.includes('sing-box') || 客户端小写.includes('singbox') || 网址.searchParams.has('sb') || 网址.searchParams.has('singbox')) {
        目标地址 = `${转换协议}://${转换器地址}/sub?target=singbox&url=${encodeURIComponent(目标地址)}&config=${规则地址}&emoji=true&scv=${跳过验证}&new_name=true`;
        采用编码 = false;
    }

    let 输出内容 = '';
    if (!外部订阅器 && 采用编码) {
        输出内容 = 生成本地节点文本(伪装域名, 伪装标识, 节点池, 明文池, 附加链接, 上下文);
    } else {
        const 响应 = await fetch(目标地址, { headers: { 'User-Agent': 字典.客户端标识 } });
        输出内容 = await 响应.text();
    }

    if (是否伪装请求) return 输出内容;
    return 还原真实信息(输出内容, 上下文.主标识, 主机名, 伪装标识, 伪装域名, 采用编码);
}

function 生成本地节点文本(主机, 标识, 加密池, 明文池, 附加链接, 上下文) {
    const 格式化单条 = (条目, 是否加密) => {
        let 地址 = 条目, 端口 = 是否加密 ? '443' : '80', 备注 = '';
        if (条目.includes('#')) [条目, 备注] = 条目.split('#');
        if (条目.includes(']:')) {
            [地址, 端口] = 条目.split(']:');
            地址 += ']';
        } else if (条目.includes(':')) {
            [地址, 端口] = 条目.split(':');
        }
        备注 = 备注 || 地址;
        let 路径 = 上下文.隧道路径;
        if (是否加密) {
            const 匹配中继 = 上下文.中继池.find(项 => 项.includes(地址));
            if (匹配中继) 路径 = `/proxyip=${匹配中继}`;
            return `${字典.协议名}://${标识}@${地址}:${端口}${字典.加密参数}${主机}&fp=random&type=ws&host=${主机}&path=${encodeURIComponent(路径)}${上下文.跳过证书参数}#${encodeURIComponent(备注)}`;
        }
        return `${字典.协议名}://${标识}@${地址}:${端口}${字典.明文参数}${主机}&path=${encodeURIComponent(路径)}#${encodeURIComponent(备注)}`;
    };

    const 结果集 = 加密池.map(项 => 格式化单条(项, true));
    if (上下文.强制明文 === 'true') 结果集.push(...明文池.map(项 => 格式化单条(项, false)));
    if (附加链接.length) 结果集.push(...附加链接);
    return btoa(结果集.join('\n'));
}

function 解析流参数(上下文) {
    const { 网址 } = 上下文;
    const 路径 = 网址.pathname;
    const 路径小写 = 路径.toLowerCase();

    if (网址.searchParams.has('socks5') || 网址.searchParams.has('http')) {
        上下文.代理地址 = 网址.searchParams.get('socks5') || 网址.searchParams.get('http');
        上下文.启用网页代理 = 网址.searchParams.has('http');
    }
    if (网址.searchParams.has('globalproxy')) 上下文.代理规则组 = ['all in'];

    if (路径小写.includes('/socks5=')) {
        上下文.代理地址 = 路径.split('5=')[1];
    } else if (路径小写.includes('/socks://') || 路径小写.includes('/socks5://') || 路径小写.includes('/http://')) {
        上下文.启用网页代理 = 路径小写.includes('/http://');
        let 提取地址 = 路径.split('://')[1].split('#')[0];
        if (提取地址.includes('@')) {
            const 分割位 = 提取地址.lastIndexOf('@');
            let 凭据 = 提取地址.substring(0, 分割位).replaceAll('%3D', '=');
            if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(凭据) && !凭据.includes(':')) 凭据 = atob(凭据);
            提取地址 = `${凭据}@${提取地址.substring(分割位 + 1)}`;
        }
        上下文.代理地址 = 提取地址;
        上下文.代理规则组 = ['all in'];
    }

    if (上下文.代理地址) {
        try {
            解析代理配置(上下文.代理地址);
            上下文.启用外部代理 = true;
        } catch {
            上下文.启用外部代理 = false;
        }
    }

    if (网址.searchParams.has('proxyip')) {
        上下文.中继节点 = 网址.searchParams.get('proxyip');
        上下文.启用外部代理 = false;
    } else {
        const 匹配 = 路径.match(/\/(proxyip=|proxyip\.|pyip=|ip=)(.+)/i);
        if (匹配) {
            上下文.中继节点 = 匹配[1].toLowerCase() === 'proxyip.' ? `proxyip.${匹配[2]}` : 匹配[2];
            上下文.启用外部代理 = false;
        }
    }
}

async function 处理数据流(请求, 上下文) {
    const [客户端, 服务端] = Object.values(new WebSocketPair());
    服务端.accept();

    let 远端套接字 = null, 域名写入器 = null, 是否域名查询 = false;

    new ReadableStream({
        start(控制器) {
            服务端.addEventListener('message', 事件 => 控制器.enqueue(事件.data));
            服务端.addEventListener('close', () => { 远端套接字?.close(); 控制器.close(); });
            服务端.addEventListener('error', () => { 远端套接字?.close(); 控制器.error(); });
            const 早期数据 = 请求.headers.get('sec-websocket-protocol');
            if (早期数据) {
                try {
                    控制器.enqueue(Uint8Array.from(atob(早期数据.replace(/-/g, '+').replace(/_/g, '/')), 字符 => 字符.charCodeAt(0)).buffer);
                } catch {}
            }
        }
    }).pipeTo(new WritableStream({
        async write(数据包) {
            if (是否域名查询) return 域名写入器?.write(数据包);
            if (远端套接字) {
                const 写入器 = 远端套接字.writable.getWriter();
                await 写入器.write(数据包);
                写入器.releaseLock();
                return;
            }

            if (数据包.byteLength < 24) return;
            const 头部字节 = new Uint8Array(数据包.slice(1, 17));
            if (!核对标识字节(头部字节, 上下文.主标识) && !(上下文.备用标识 && 核对标识字节(头部字节, 上下文.备用标识))) return;

            const 视图 = new DataView(数据包);
            const 协议版本 = 视图.getUint8(0);
            const 附加长度 = 视图.getUint8(17);
            const 指令 = 视图.getUint8(18 + 附加长度);
            if (指令 !== 1 && 指令 !== 2) return;

            let 指针 = 19 + 附加长度;
            const 目标端口 = 视图.getUint16(指针);
            const 地址类型 = 视图.getUint8(指针 + 2);
            指针 += 3;

            let 目标地址 = '';
            if (地址类型 === 1) {
                目标地址 = `${视图.getUint8(指针)}.${视图.getUint8(指针 + 1)}.${视图.getUint8(指针 + 2)}.${视图.getUint8(指针 + 3)}`;
                指针 += 4;
            } else if (地址类型 === 2) {
                const 长度 = 视图.getUint8(指针++);
                目标地址 = new TextDecoder().decode(数据包.slice(指针, 指针 + 长度));
                指针 += 长度;
            } else if (地址类型 === 3) {
                const 段组 = [];
                for (let i = 0; i < 8; i++, 指针 += 2) 段组.push(视图.getUint16(指针).toString(16));
                目标地址 = 段组.join(':');
            } else return;

            if (上下文.拦截列表.includes(目标地址)) throw new Error(`Rejected: ${目标地址}`);
            const 响应头 = new Uint8Array([协议版本, 0]);
            const 净荷 = 数据包.slice(指针);

            if (指令 === 2) {
                if (目标端口 !== 53) return;
                是否域名查询 = true;
                let 已发头部 = false;
                const { readable, writable } = new TransformStream({
                    transform(分片, 控制器) {
                        for (let i = 0; i < 分片.byteLength;) {
                            const 长度 = new DataView(分片.slice(i, i + 2)).getUint16(0);
                            控制器.enqueue(分片.slice(i + 2, i + 2 + 长度));
                            i += 2 + 长度;
                        }
                    }
                });
                readable.pipeTo(new WritableStream({
                    async write(查询包) {
                        try {
                            const 响应 = await fetch('https://1.1.1.1/dns-query', {
                                method: 'POST',
                                headers: { 'content-type': 'application/dns-message' },
                                body: 查询包
                            });
                            if (服务端.readyState === 1) {
                                const 结果 = new Uint8Array(await 响应.arrayBuffer());
                                服务端.send(new Uint8Array([...(已发头部 ? [] : 响应头), 结果.length >> 8, 结果.length & 0xff, ...结果]));
                                已发头部 = true;
                            }
                        } catch {}
                    }
                }));
                域名写入器 = writable.getWriter();
                return 域名写入器.write(净荷);
            }

            const 命中代理规则 = 上下文.启用外部代理 && 上下文.代理规则组.some(规则 => {
                if (规则 === 'all in' || 规则 === '*') return true;
                return new RegExp(`^${规则.replace(/\*/g, '.*')}$`, 'i').test(目标地址);
            });

            let 套接字 = null;
            if (命中代理规则) {
                套接字 = 上下文.启用网页代理 ? await 建立网页代理连接(目标地址, 目标端口, 上下文.代理地址) : await 建立套接字代理连接(目标地址, 目标端口, 上下文.代理地址);
            } else {
                try {
                    套接字 = 建立连接({ hostname: 目标地址, port: 目标端口 });
                    await 套接字.opened;
                } catch {
                    if (上下文.启用外部代理) {
                        套接字 = 上下文.启用网页代理 ? await 建立网页代理连接(目标地址, 目标端口, 上下文.代理地址) : await 建立套接字代理连接(目标地址, 目标端口, 上下文.代理地址);
                    } else {
                        const [中继主机, 中继端口] = await 解析中继目标(上下文.中继节点);
                        try {
                            套接字 = 建立连接({ hostname: 中继主机, port: 中继端口 });
                            await 套接字.opened;
                        } catch {
                            套接字 = 建立连接({ hostname: 字典.兜底节点, port: 1 });
                            await 套接字.opened;
                        }
                    }
                }
            }

            if (!套接字) return;
            远端套接字 = 套接字;
            const 写入器 = 套接字.writable.getWriter();
            await 写入器.write(净荷);
            写入器.releaseLock();

            let 已发响应头 = false;
            套接字.readable.pipeTo(new WritableStream({
                write(分片) {
                    if (服务端.readyState === 1) {
                        服务端.send(已发响应头 ? 分片 : new Uint8Array([...响应头, ...new Uint8Array(分片)]));
                        已发响应头 = true;
                    }
                },
                close: () => 服务端.readyState === 1 && 服务端.close(),
                abort: () => 服务端.readyState === 1 && 服务端.close()
            })).catch(() => {});
        }
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: 客户端 });
}

// 代理连接与辅助工具函数
async function 建立套接字代理连接(目标主机, 目标端口, 代理配置串) {
    const { 账号, 密码, 主机, 端口 } = 解析代理配置(代理配置串);
    const 套接字 = 建立连接({ hostname: 主机, port: 端口 });
    await 套接字.opened;
    const 写 = 套接字.writable.getWriter();
    const 读 = 套接字.readable.getReader();
    await 写.write(new Uint8Array([5, 2, 0, 2]));
    const 协商响应 = (await 读.read()).value;
    if (协商响应[1] === 2 && 账号) {
        const 账字节 = new TextEncoder().encode(账号);
        const 密字节 = new TextEncoder().encode(密码);
        await 写.write(new Uint8Array([1, 账字节.length, ...账字节, 密字节.length, ...密字节]));
        await 读.read();
    }
    const 域名字节 = new TextEncoder().encode(目标主机);
    await 写.write(new Uint8Array([5, 1, 0, 3, 域名字节.length, ...域名字节, 目标端口 >> 8, 目标端口 & 0xff]));
    await 读.read();
    写.releaseLock();
    读.releaseLock();
    return 套接字;
}

async function 建立网页代理连接(目标主机, 目标端口, 代理配置串) {
    const { 账号, 密码, 主机, 端口 } = 解析代理配置(代理配置串);
    const 套接字 = 建立连接({ hostname: 主机, port: 端口 });
    await 套接字.opened;
    let 报文 = `CONNECT ${目标主机}:${目标端口} HTTP/1.1\r\nHost: ${目标主机}:${目标端口}\r\n`;
    if (账号 && 密码) 报文 += `Proxy-Authorization: Basic ${btoa(`${账号}:${密码}`)}\r\n`;
    报文 += `Proxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;

    const 写 = 套接字.writable.getWriter();
    await 写.write(new TextEncoder().encode(报文));
    写.releaseLock();

    const 读 = 套接字.readable.getReader();
    let 缓存 = new Uint8Array(0);
    while (true) {
        const { value, done } = await 读.read();
        if (done) throw new Error('Proxy closed');
        const 新缓存 = new Uint8Array(缓存.length + value.length);
        新缓存.set(缓存);
        新缓存.set(value, 缓存.length);
        缓存 = 新缓存;
        const 文本 = new TextDecoder().decode(缓存);
        if (文本.includes('\r\n\r\n')) {
            if (!文本.startsWith('HTTP/1.1 200') && !文本.startsWith('HTTP/1.0 200')) throw new Error('Proxy rejected');
            break;
        }
    }
    读.releaseLock();
    return 套接字;
}

function 解析代理配置(地址串) {
    const 分割位 = 地址串.lastIndexOf('@');
    let [后段, 前段] = 分割位 === -1 ? [地址串, undefined] : [地址串.substring(分割位 + 1), 地址串.substring(0, 分割位)];
    let 账号, 密码, 主机, 端口 = 80;
    if (前段) {
        const 凭据 = 前段.split(':');
        if (凭据.length !== 2) throw new Error('Invalid auth');
        [账号, 密码] = 凭据;
    }
    if (后段.includes(']:')) {
        端口 = Number(后段.split(']:')[1].replace(/[^\d]/g, ''));
        主机 = 后段.split(']:')[0] + ']';
    } else if (后段.includes(':')) {
        const 片段 = 后段.split(':');
        端口 = Number(片段.pop().replace(/[^\d]/g, ''));
        主机 = 片段.join(':');
    } else {
        主机 = 后段;
    }
    return { 账号, 密码, 主机, 端口 };
}

async function 解析中继目标(中继串) {
    let 目标 = 中继串.toLowerCase();
    if (目标.includes('.william')) {
        try {
            const 响应 = await fetch(`https://1.1.1.1/dns-query?name=${目标}&type=TXT`, { headers: { 'Accept': 'application/dns-json' } });
            if (响应.ok) {
                const 数据 = await 响应.json();
                const 记录 = (数据.Answer || []).filter(r => r.type === 16).map(r => r.data)[0];
                if (记录) {
                    const 列表 = 记录.replace(/^"|"$/g, '').replace(/\\010|\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
                    if (列表.length) 目标 = 列表[Math.floor(Math.random() * 列表.length)];
                }
            }
        } catch {}
    }
    let 地址 = 目标, 端口 = 443;
    if (目标.includes('.tp')) {
        const 匹配 = 目标.match(/\.tp(\d+)/);
        if (匹配) 端口 = parseInt(匹配[1], 10);
    } else if (目标.includes(']:')) {
        const 片段 = 目标.split(']:');
        地址 = 片段[0] + ']';
        端口 = parseInt(片段[1], 10) || 443;
    } else if (目标.includes(':') && !目标.startsWith('[')) {
        const 冒号位 = 目标.lastIndexOf(':');
        地址 = 目标.slice(0, 冒号位);
        端口 = parseInt(目标.slice(冒号位 + 1), 10) || 443;
    }
    return [地址, 端口];
}

async function 拉取远程列表(接口组, 上下文) {
    if (!接口组 || !接口组.length) return [];
    const 控制器 = new AbortController();
    const 定时器 = setTimeout(() => 控制器.abort(), 2500);
    let 汇总文本 = '';
    try {
        const 结果集 = await Promise.allSettled(接口组.map(网址 => fetch(网址, { signal: 控制器.signal }).then(r => r.ok ? r.text() : Promise.reject())));
        for (const [索引, 结果] of 结果集.entries()) {
            if (结果.status !== 'fulfilled') continue;
            const 内容 = 结果.value;
            const 行组 = 内容.split(/\r?\n/);
            if (行组[0] && 行组[0].split(',').length > 3) {
                const 备注 = 接口组[索引].match(/id=([^&]*)/)?.[1] || '';
                const 端口 = 接口组[索引].match(/port=([^&]*)/)?.[1] || '443';
                for (let i = 1; i < 行组.length; i++) {
                    const 首列 = 行组[i].split(',')[0];
                    if (首列) {
                        汇总文本 += `${首列}:${端口}${备注 ? `#${备注}` : ''}\n`;
                        if (接口组[索引].includes('proxyip=true')) 上下文.中继池.push(`${首列}:${端口}`);
                    }
                }
            } else {
                if (接口组[索引].includes('proxyip=true')) {
                    上下文.中继池.push(...拆分列表(内容).map(项 => 项.split('#')[0]).filter(Boolean));
                }
                汇总文本 += 内容 + '\n';
            }
        }
    } catch {} finally {
        clearTimeout(定时器);
    }
    return 拆分列表(汇总文本);
}

async function 解析测速表格(表格组, 要求加密, 上下文) {
    if (!表格组 || !表格组.length) return [];
    const 结果集 = [];
    for (const 网址 of 表格组) {
        try {
            const 响应 = await fetch(网址);
            if (!响应.ok) continue;
            const 行组 = (await 响应.text()).split(/\r?\n/);
            const 表头 = 行组[0]?.split(',') || [];
            const 加密列 = 表头.indexOf('TLS');
            if (加密列 === -1) continue;
            for (let i = 1; i < 行组.length; i++) {
                const 列 = 行组[i].split(',');
                if (列[加密列]?.toUpperCase() === 要求加密 && parseFloat(列[列.length - 1]) > 上下文.速度下限) {
                    结果集.push(`${列[0]}:${列[1]}#${列[加密列 + 上下文.备注偏移]}`);
                    if (网址.includes('proxyip=true') && 要求加密 === 'TRUE') 上下文.中继池.push(`${列[0]}:${列[1]}`);
                }
            }
        } catch {}
    }
    return 结果集;
}

async function 处理存储编辑(请求, 环境) {
    if (!环境.KV) return new Response('未绑定 KV 存储空间', { status: 400 });
    if (请求.method === 'POST') {
        await 环境.KV.put('ADD.txt', await 请求.text());
        return new Response('保存成功');
    }
    const 内容 = await 环境.KV.get('ADD.txt') || '';
    const 页面 = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>节点列表管理</title><style>body{max-width:720px;margin:20px auto;font-family:sans-serif;padding:0 15px}textarea{width:100%;height:420px;font-family:monospace;padding:10px;box-sizing:border-box}button{padding:8px 20px;background:#4a90e2;color:#fff;border:none;border-radius:4px;cursor:pointer;margin-top:10px}</style></head><body><h3>优选节点与订阅源管理 (ADD.txt)</h3><textarea id="t">${内容}</textarea><br><button onclick="fetch(location.href,{method:'POST',body:document.getElementById('t').value}).then(r=>r.text()).then(alert)">保存修改</button></body></html>`;
    return new Response(页面, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

function 渲染简易面板(上下文, 编码订阅) {
    const 基础链接 = `https://${上下文.主机名}/${上下文.动态密钥}`;
    return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${上下文.配置名称}</title><style>body{max-width:760px;margin:30px auto;font-family:sans-serif;padding:0 16px;background:#f4f7f9;color:#333}.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.06);margin-bottom:16px}code{display:block;background:#f0f4f8;padding:10px;border-radius:6px;word-break:break-all;margin:8px 0;cursor:pointer}</style></head><body><div class="card"><h2>🚀 ${上下文.配置名称}</h2><p>点击下方链接直接复制：</p><b>通用 / Base64 订阅：</b><code onclick="navigator.clipboard.writeText(this.innerText).then(()=>alert('已复制'))">${基础链接}?sub</code><b>Clash 订阅：</b><code onclick="navigator.clipboard.writeText(this.innerText).then(()=>alert('已复制'))">${基础链接}?clash</code><b>Sing-box 订阅：</b><code onclick="navigator.clipboard.writeText(this.innerText).then(()=>alert('已复制'))">${基础链接}?sb</code><p><a href="${上下文.网址.pathname}/edit">📝 在线编辑 KV 节点列表</a></p></div><div class="card"><h4>节点明文预览：</h4><code style="white-space:pre-wrap">${atob(编码订阅)}</code></div></body></html>`;
}

async function 反向代理网页(源配置, 请求网址) {
    const 列表 = 拆分列表(源配置);
    const 目标 = new URL(列表[Math.floor(Math.random() * 列表.length)]);
    目标.pathname = 目标.pathname.replace(/\/$/, '') + 请求网址.pathname;
    const 响应 = await fetch(目标.toString());
    return new Response(响应.body, { status: 响应.status, headers: 响应.headers });
}

function 拆分列表(文本) {
    if (!文本) return [];
    return 文本.replace(/[\t"'\r\n]+/g, ',').replace(/,+/g, ',').replace(/^,|,$/g, '').split(',').filter(Boolean);
}

function 校验标识格式(字符串) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(字符串);
}

function 核对标识字节(字节数组, 标识字符串) {
    const 十六进制 = 标识字符串.replace(/-/g, '');
    for (let i = 0; i < 16; i++) {
        if (字节数组[i] !== parseInt(十六进制.substr(i * 2, 2), 16)) return false;
    }
    return true;
}

function 还原真实信息(文本, 真标识, 真主机, 假标识, 假主机, 是否编码) {
    if (是否编码) 文本 = atob(文本);
    文本 = 文本.replace(new RegExp(假标识, 'g'), 真标识).replace(new RegExp(假主机, 'g'), 真主机);
    return 是否编码 ? btoa(文本) : 文本;
}

function 网址参数或环境变量(网址, 环境) {
    const 原始 = 网址.searchParams.get('sub') || 环境.SUB || '';
    const 匹配 = 原始.match(/^(?:https?:\/\/)?([^\/]+)/);
    return 匹配 ? 拆分列表(匹配[1])[0] || '' : '';
}

async function 双重摘要(文本) {
    const 编码器 = new TextEncoder();
    const 首轮 = Array.from(new Uint8Array(await crypto.subtle.digest('MD5', 编码器.encode(文本)))).map(b => b.toString(16).padStart(2, '0')).join('');
    const 次轮 = Array.from(new Uint8Array(await crypto.subtle.digest('MD5', 编码器.encode(首轮.slice(7, 27))))).map(b => b.toString(16).padStart(2, '0')).join('');
    return 次轮.toLowerCase();
}

async function 派生动态标识(密钥, 周期天数, 更新时点) {
    const 基准时间 = new Date(2007, 6, 7, 更新时点, 0, 0).getTime();
    const 周期毫秒 = 86400000 * 周期天数;
    const 当前周期 = Math.ceil((Date.now() + 28800000 - 基准时间) / 周期毫秒);
    const 生成 = async (种子) => {
        const 哈希 = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(种子)))).map(b => b.toString(16).padStart(2, '0')).join('');
        return `${哈希.slice(0, 8)}-${哈希.slice(8, 12)}-4${哈希.slice(13, 16)}-${(parseInt(哈希.slice(16, 18), 16) & 0x3f | 0x80).toString(16)}${哈希.slice(18, 20)}-${哈希.slice(20, 32)}`;
    };
    return Promise.all([生成(密钥 + 当前周期), 生成(密钥 + (当前周期 - 1))]);
}
