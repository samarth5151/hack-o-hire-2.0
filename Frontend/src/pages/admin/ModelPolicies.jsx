import { useState } from 'react'
import { motion } from 'framer-motion'
import { RiDatabaseLine, RiShieldUserLine, RiToggleLine, RiToggleFill, RiAddLine } from 'react-icons/ri'
import { Card, PageWrapper, PageHeader, SectionHeader, Tag, Btn } from '../../components/ui'

const policies = [
  { id: 'POL-01', name: 'Source Code / Git Secrets', type: 'Regex & Entropy', status: true,  desc: 'Blocks AWS keys, GitHub tokens, and proprietary source code markers.', action: 'Block' },
  { id: 'POL-02', name: 'PII (Customer Data)',       type: 'NER (spaCy)',     status: true,  desc: 'Blocks SSN, Credit Cards, and large batches of phone/email info.',   action: 'Redact' },
  { id: 'POL-03', name: 'Financial Records',         type: 'Regex + BERT',    status: true,  desc: 'Blocks wire instructions, routing numbers, and Swift codes.',       action: 'Block' },
  { id: 'POL-04', name: 'Internal Hostnames',        type: 'Regex',           status: false, desc: 'Prevents leakage of internal .bank.local or IP addresses.',          action: 'Alert' },
]

export default function ModelPolicies() {
  const [activePolicies, setActivePolicies] = useState(
    Object.fromEntries(policies.map(p => [p.id, p.status]))
  )

  const togglePolicy = (id) => {
    setActivePolicies(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <PageWrapper>
      <PageHeader
        title="DLP Policies & Enforcement Rules"
        sub="Configure data classification rules, actions (Block/Redact/Alert), and enforcement status."
        right={<Btn variant="primary"><RiAddLine /> New Policy</Btn>}
      />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        <div className="lg:col-span-3 space-y-4">
          <Card>
            <SectionHeader title="Active Data Loss Prevention Rules" />
            <div className="space-y-3 pt-2">
              {policies.map((pol) => {
                const isActive = activePolicies[pol.id]
                return (
                  <motion.div
                    key={pol.id}
                    className={`p-4 border rounded-xl flex items-start gap-4 transition-colors ${
                      isActive ? 'border-sky-200 bg-white shadow-sm' : 'border-slate-100 bg-slate-50'
                    }`}
                  >
                    <button
                      onClick={() => togglePolicy(pol.id)}
                      className="mt-1 flex-shrink-0 focus:outline-none"
                    >
                      {isActive ? (
                        <RiToggleFill className="text-3xl text-emerald-500" />
                      ) : (
                        <RiToggleLine className="text-3xl text-slate-300" />
                      )}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between items-start mb-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[13px] font-bold text-slate-800">{pol.name}</span>
                          <span className="text-[10px] font-mono bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded border border-slate-200">{pol.id}</span>
                        </div>
                        <span className={`text-[11px] font-bold px-2.5 py-1 rounded-lg ${
                          pol.action === 'Block' ? 'bg-red-50 text-red-600 border border-red-100' :
                          pol.action === 'Redact' ? 'bg-orange-50 text-orange-600 border border-orange-100' :
                          'bg-yellow-50 text-yellow-600 border border-yellow-100'
                        }`}>
                          Action: {pol.action}
                        </span>
                      </div>
                      <p className="text-[12px] text-slate-500 mb-2 leading-relaxed">{pol.desc}</p>
                      <div className="flex items-center gap-2">
                         <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Engine:</span>
                         <Tag>{pol.type}</Tag>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </Card>
        </div>

        <div className="space-y-4">
           <Card className="bg-sky-50 border border-sky-100">
             <div className="flex gap-3 items-center mb-3">
               <RiShieldUserLine className="text-sky-600 text-xl" />
               <h3 className="text-[13px] font-bold text-sky-900">Enforcement Mode</h3>
             </div>
             <p className="text-[11px] text-sky-700/80 mb-4">
               The DLP system is currently running in <strong>Strict Blocking</strong> mode. Redacted/Blocked payloads will not reach the external LLM platform under any circumstances.
             </p>
             <button className="w-full bg-white text-sky-600 border border-sky-300 font-bold text-[11px] py-1.5 rounded-lg hover:bg-sky-100">
               Switch to Audit Only
             </button>
           </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
