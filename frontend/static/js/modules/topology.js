/**
 * 子资产拓扑图 Canvas 渲染模块 (Sub-Asset Topology Canvas Module)
 * 基于原生 HTML5 Canvas 实现，无第三方依赖
 */

export class SubAssetTopology {
    constructor(canvasElement) {
        this.canvas = canvasElement;
        this.ctx = canvasElement.getContext('2d');
        this.nodes = [];
        this.links = [];
        this.width = canvasElement.width || 800;
        this.height = canvasElement.height || 500;
    }

    render(data) {
        const { subAssets = [], ipClusters = [], riskProfiles = [] } = data;
        this.ctx.clearRect(0, 0, this.width, this.height);
        
        if (!subAssets.length) {
            this.ctx.fillStyle = '#64748b';
            this.ctx.font = '14px sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.fillText('暂无子资产拓扑数据', this.width / 2, this.height / 2);
            return;
        }

        // 绘制主中心与外围 IP/子资产节点
        const centerX = this.width / 2;
        const centerY = this.height / 2;
        
        // 绘制主目标中心
        this.ctx.beginPath();
        this.ctx.arc(centerX, centerY, 24, 0, 2 * Math.PI);
        this.ctx.fillStyle = '#0284c7';
        this.ctx.fill();
        this.ctx.fillStyle = '#ffffff';
        this.ctx.font = 'bold 12px sans-serif';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'middle';
        this.ctx.fillText('ROOT', centerX, centerY);

        // 绘制辐射节点
        const angleStep = (2 * Math.PI) / subAssets.length;
        const radius = Math.min(this.width, this.height) * 0.38;

        subAssets.forEach((sa, idx) => {
            const angle = idx * angleStep;
            const nx = centerX + radius * Math.cos(angle);
            const ny = centerY + radius * Math.sin(angle);

            // 绘制连线
            this.ctx.beginPath();
            this.ctx.moveTo(centerX, centerY);
            this.ctx.lineTo(nx, ny);
            this.ctx.strokeStyle = '#cbd5e1';
            this.ctx.lineWidth = 1.5;
            this.ctx.setLineDash([4, 4]);
            this.ctx.stroke();
            this.ctx.setLineDash([]);

            // 风险等级着色
            let color = '#10b981';
            if (sa.risk_level === 'CRITICAL') color = '#ef4444';
            else if (sa.risk_level === 'HIGH') color = '#f97316';
            else if (sa.risk_level === 'MEDIUM') color = '#f59e0b';

            // 节点圆形
            this.ctx.beginPath();
            this.ctx.arc(nx, ny, 16, 0, 2 * Math.PI);
            this.ctx.fillStyle = color;
            this.ctx.fill();
            this.ctx.strokeStyle = '#ffffff';
            this.ctx.lineWidth = 2;
            this.ctx.stroke();

            // 文本标签
            this.ctx.fillStyle = '#0f172a';
            this.ctx.font = '11px monospace';
            this.ctx.textAlign = 'center';
            const label = sa.hostname || (sa.ips && sa.ips[0]) || 'sub';
            this.ctx.fillText(label.length > 18 ? label.slice(0, 16) + '..' : label, nx, ny + 26);
        });
    }
}
