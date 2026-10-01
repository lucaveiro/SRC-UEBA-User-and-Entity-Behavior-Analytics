# Adenda ao Relatório — Revisão da Regra R1 (Deteção de BotNet Interna)
**Projeto 1 - Segurança em Redes de Comunicações** - Não foi feito alterações
**Projeto 2 — Segurança em Redes de Comunicação**
**Ficheiro de referência:** `Report.md` (secções 5.1 e 6.1)
**Âmbito deste documento:** apenas a regra R1, na sequência da avaliação da submissão anterior.

## Autores

| Nome         | Número |
| ------------ | ------ |
| Ruben Lopes  | 103009 |
| Lucas Rebelo | 123934 |

---

---

## 1. Diagnóstico da versão anterior

Na submissão anterior, a secção 5.1 do relatório descrevia a regra R1 como um predicado sobre **duas** métricas combinadas — `n_dst_servers` (fan‑out) e `cv_interval` (regularidade temporal) — e incluía um gráfico de dispersão (`fig_internal_fanout_cv.png`) a justificar precisamente essa combinação.

No entanto, a implementação efetivamente aplicada no notebook (`Notebook 02 — Célula 2`) usava apenas:

```python
r1_flagged = r1_test[(r1_test['cv_interval'] < CV_THRESH) & (r1_test['n_flows'] >= 50)]
```

ou seja, o critério real de deteção baseava-se unicamente em `cv_interval` (regularidade temporal) e num limiar mínimo de amostragem (`n_flows ≥ 50`) — a métrica `n_dst_servers`, apesar de calculada e usada no gráfico de justificação, **nunca entrava no filtro de deteção**. Isto tinha duas consequências:

1. **Incoerência entre a justificação teórica e a regra aplicada** — o texto e o gráfico prometiam uma deteção por fan‑out *e* regularidade, mas o código só verificava regularidade.
2. **Cobertura reduzida a um único vetor de ataque** — uma botnet que comunique com muitos destinos mas sem uma cadência extremamente regular (ou que se propague lateralmente dentro da rede interna, sem exibir beaconing externo) não seria detetada. Não existia qualquer análise ao tráfego interno‑interno (host a host), apesar de a propagação lateral ser um comportamento característico de dispositivos comprometidos.

Estes dois pontos foram identificados como a causa provável da avaliação insuficiente desta regra.

---

## 2. Alterações efetuadas

A regra R1 foi reformulada para ser composta por **duas sub‑regras complementares**, combinadas com **OU** (um host interno é sinalizado se qualquer uma disparar):

| | Sub-regra | O que deteta | Métricas |
|---|-----------|---------------|----------|
| **R1.A** | Comportamento do host | Beaconing clássico: fan-out elevado **e** tráfego demasiado regular | `n_dst_servers`, `cv_interval` |
| **R1.B** | Comportamento do par interno (`src_ip → dst_ip`) | Propagação lateral: comunicações internas novas ou com aumento de volume | pares `(src_ip, dst_ip)`, `total_bytes_pair` |

### 2.1. R1.A — agora aplica de facto as duas métricas

A condição de deteção passou a exigir a verificação simultânea (E lógico) das duas métricas já justificadas no gráfico da secção 5.1, corrigindo a incoerência anterior:

- `n_dst_servers > mean_treino + 3 × std_treino`
- `cv_interval < mean_treino − 1 × std_treino`

Os limiares deixaram também de ser derivados por margens percentuais arbitrárias sobre o mínimo/máximo do treino (ex. `min_treino × 0.95`), passando a usar média e desvio padrão — uma base estatística mais defensável e consistente com o critério já usado nas restantes regras (R2, R3, R6).

### 2.2. R1.B — nova sub-regra: deteção de propagação lateral

Esta sub-regra é inteiramente nova e cobre o tráfego interno‑interno, anteriormente não analisado por R1. Passos:

1. Agregam-se por par `(src_ip, dst_ip)` todos os fluxos cujo destino é também um IP interno.
2. Identificam-se os servidores internos "populares" — destinos contactados por mais de 10 clientes distintos no histórico (ex. servidores de ficheiros/backup/atualizações) — e excluem-se do cálculo do threshold de volume, para não sinalizar tráfego servidor legítimo.
3. Um par é suspeito se o destino **não** for um servidor popular conhecido, e:
   - o par nunca foi observado no histórico de treino (**comunicação nova**); **ou**
   - o volume do par excede `mean_treino + 3 × std_treino` dos pares não‑servidor do histórico (**aumento significativo**).
4. Um `src_ip` é sinalizado por R1.B se participar em pelo menos um par suspeito.

Neste dataset em particular, todo o tráfego interno‑interno do histórico tem como destino um servidor popular, pelo que não há pares "normais" para calibrar o threshold de volume; essa condição fica desativada (`threshold = +∞`) e R1.B passa, na prática, a assentar na deteção de comunicações internas novas — ainda assim suficiente para identificar propagação lateral no conjunto de teste.

---

## 3. Resultados

Aplicando a regra revista a `internal_test3.json` (dataset da equipa), com thresholds derivados de `internal_train3.json`:

**Thresholds calculados:**

| Threshold | Valor | Base |
|---|---|---|
| `THRESHOLD_DST_R1` (R1.A) | 256.41 | mean=122.62, std=44.60 |
| `THRESHOLD_CV_LOW_R1` (R1.A) | 5.27 | mean=11.52, std=6.25 |
| Servidores internos populares (excluídos de R1.B) | 192.168.103.225, 192.168.103.238, 192.168.103.240 | > 10 clientes distintos no treino |
| `THRESHOLD_BYTES_PAIR_R1` (R1.B) | +∞ (desativado) | sem pares não-servidor no treino |

**IPs sinalizados no teste:**

| src_ip           | disparou_A | disparou_B | Motivo                            |
|------------------|------------|------------|-----------------------------------|
| 192.168.110.116  | True       | False      | A (host: fan-out + regularidade)  |
| 192.168.110.152  | False      | True       | B (par: comunicação nova/aumento) |
| 192.168.110.57   | False      | True       | B (par: comunicação nova/aumento) |
| 192.168.110.59   | True       | False      | A (host: fan-out + regularidade)  |
| 192.168.110.96   | False      | True       | B (par: comunicação nova/aumento) |

**Total: 5 IPs sinalizados** (anteriormente: apenas 1 IP com comportamento suspeito, que no novo baseline e nos limiares recalibrados já não é sinalizado por R1.A isoladamente).

No dataset10, a Regra R1 identifica como suspeitos os hosts internos 192.168.110.116, 192.168.110.152, 192.168.110.57, 192.168.110.59 e 192.168.110.96, combinando dois mecanismos: o modo A (fan‑out elevado e regularidade temporal anómala ao nível do host) e o modo B (novos pares de comunicação ou aumentos significativos de tráfego para destinos específicos, excluindo servidores corporativos comuns).

Note-se que 192.168.110.116 e 192.168.110.59 são sinalizados pela componente A da R1 (fan‑out interno + regularidade temporal), enquanto os restantes (192.168.110.152, 192.168.110.57 e 192.168.110.96) são sinalizados pela componente B (par de comunicação novo ou com aumento relevante para além do padrão de treino). Esta combinação de evidências ao nível de host e de par de comunicação torna o conjunto de suspeitos mais robusto, porque cada IP não é apenas “ruído estatístico” numa métrica, mas apresenta um padrão de comportamento coerente com o que se esperaria de um dispositivo comprometido numa rede corporativa.
---

## 4. Resumo das alterações

| Aspeto | Submissão anterior | Submissão revista |
|---|---|---|
| Métricas realmente aplicadas na deteção | Só `cv_interval` (apesar do texto/gráfico prometerem também `n_dst_servers`) | `n_dst_servers` **e** `cv_interval` em conjunto (R1.A) |
| Vetores de ataque cobertos | 1 (beaconing externo regular) | 2 (beaconing externo **e** propagação lateral interna) |
| Base dos thresholds | Margens percentuais arbitrárias sobre mínimo/máximo do treino | Média ± desvio padrão do treino, consistente com as restantes regras |
| Tráfego interno-interno analisado | Não | Sim (R1.B) |
| IPs sinalizados no teste | 1 | 5 |

Estas alterações não requerem mudanças a `Report.md` fora das secções 5.1 (definição/justificação da regra) e 6.1 (resultados) e das respetivas entradas nas tabelas-resumo das secções 6.7 e 7.4, que devem ser atualizadas com os 5 IPs acima em vez do único IP da versão anterior.
