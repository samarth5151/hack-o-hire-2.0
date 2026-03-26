import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  RiFolderOpenLine, RiFileDamageLine, RiCheckboxCircleLine,
  RiAlertLine, RiDownloadLine, RiLoader4Line, RiFileList3Line
} from 'react-icons/ri'
import {
  Card, Btn, RiskBadge, ScoreMeter, ResultPanel,
  PageWrapper, PageHeader, SectionHeader, SidebarStat,
} from '../components/ui'

const fileTypes = ['PDF', 'DOCX', 'XLSX', 'EXE / PE', 'ZIP / RAR', 'JAR', 'PY / JS', 'Images']

export default function AttachmentAnalyzer() {
  const [scannedData, setScannedData] = useState(null)
  const [isScanning, setIsScanning] = useState(false)
  const [error, setError] = useState(null)
  const fileInputRef = useRef(null)

  const handleFileUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return

    setIsScanning(true)
    setError(null)
    setScannedData(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch('/api/attachment-scan/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) throw new Error('Analysis request failed')

      const data = await res.json()
      setScannedData(data)
    } catch (err) {
      setError(err.message || 'Failed to scan the attachment.')
    } finally {
      setIsScanning(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const triggerUpload = () => {
    if (fileInputRef.current) fileInputRef.current.click()
  }

  return (
    <PageWrapper>
      <PageHeader
        title="Malicious Attachment Analyzer"
        sub="Static analyzer rules (YARA, Magic Bytes) · Office macros · PDF stream analysis · MalwareBazaar hashing"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <div 
              onClick={triggerUpload} 
              className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-colors ${
                isScanning ? 'bg-slate-50 border-slate-200' : 'border-sky-200 bg-sky-50 hover:bg-sky-100 hover:border-sky-300'
              }`}
            >
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileUpload} 
                className="hidden" 
              />
              {isScanning ? (
                <div className="flex flex-col items-center text-slate-500">
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
                  >
                    <RiLoader4Line className="text-4xl mb-3 text-sky-500" />
                  </motion.div>
                  <h3 className="text-sm font-bold text-slate-700">Analyzing...</h3>
                  <p className="text-xs mt-1">Extracting streams and matching models, please wait.</p>
                </div>
              ) : (
                <div className="flex flex-col items-center text-sky-600">
                  <RiFolderOpenLine className="text-4xl mb-3" />
                  <h3 className="text-sm font-bold text-slate-800">Drop file here or click to upload</h3>
                  <p className="text-xs text-slate-500 mt-1">PDF, DOCX, XLSX, EXE, ZIP, JAR · Max 100 MB</p>
                </div>
              )}
            </div>
            {error && (
              <div className="mt-4 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2">
                <RiAlertLine /> {error}
              </div>
            )}
          </Card>

          <AnimatePresence>
            {scannedData && (
              <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-4">
                <Card>
                  {/* File header */}
                  <div className="flex items-center justify-between mb-5">
                    <div>
                      <p className="text-[14px] font-bold text-slate-800">{scannedData.filename || 'Unknown File'}</p>
                      <p className="text-[11px] text-slate-400">{(scannedData.file_size_kb || 0).toFixed(2)} KB · Extracted successfully</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <ScoreMeter score={100 - (scannedData.risk_score || 0)} size={80} />
                      <RiskBadge level={
                        scannedData.risk_label === "Critical" ? "critical" :
                        scannedData.risk_label === "High" ? "high" :
                        scannedData.risk_label === "Medium" ? "medium" :
                        scannedData.risk_label === "Low" ? "low" : "safe"
                      } />
                    </div>
                  </div>

                  {/* Real Stats */}
                  <div className="mb-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                       <motion.div className="p-3 rounded-xl border bg-slate-50 border-slate-100 flex flex-col items-center text-center">
                         <span className="text-xs text-slate-500">Critical</span>
                         <span className="text-lg font-bold text-red-600">{scannedData.critical_count || 0}</span>
                       </motion.div>
                       <motion.div className="p-3 rounded-xl border bg-slate-50 border-slate-100 flex flex-col items-center text-center">
                         <span className="text-xs text-slate-500">High</span>
                         <span className="text-lg font-bold text-orange-500">{scannedData.high_count || 0}</span>
                       </motion.div>
                       <motion.div className="p-3 rounded-xl border bg-slate-50 border-slate-100 flex flex-col items-center text-center">
                         <span className="text-xs text-slate-500">Medium</span>
                         <span className="text-lg font-bold text-amber-500">{scannedData.medium_count || 0}</span>
                       </motion.div>
                       <motion.div className="p-3 rounded-xl border bg-slate-50 border-slate-100 flex flex-col items-center text-center">
                         <span className="text-xs text-slate-500">Total Findings</span>
                         <span className="text-lg font-bold text-slate-700">{scannedData.total_findings || 0}</span>
                       </motion.div>
                    </div>
                  </div>

                  <ResultPanel level={scannedData.risk_label === "Clean" ? "safe" : (scannedData.risk_label === "Critical" || scannedData.risk_label === "High" ? "danger" : "warning")}>
                    <strong>Summary:</strong> {scannedData.human_summary || "Scan completed."}
                    <div className="mt-1 text-xs opacity-90"><br /><strong>Recommendation:</strong> {scannedData.recommended_action}</div>
                  </ResultPanel>

                  <div className="flex gap-2 mt-4">
                    {scannedData.risk_score > 0 && <Btn variant="danger"><RiFileDamageLine /> Quarantine</Btn>}
                    <Btn variant="ghost"><RiDownloadLine /> Export Report</Btn>
                  </div>
                </Card>
                
                {/* Content Analysis Placeholder Area */}
                <Card>
                   <div className="flex items-start gap-4">
                       <div className="bg-sky-100 p-3 rounded-full shrink-0">
                           <RiFileList3Line className="text-sky-600 text-xl" />
                       </div>
                       <div className="flex-1">
                           <h4 className="text-sm font-bold text-slate-800 mb-1">AI Content Analysis Score</h4>
                           <p className="text-xs text-slate-500 mb-3">
                               Analyzing the extracted semantic content of the document for phishing lures, urgency formatting, and financial instructions.
                           </p>
                           {scannedData.content_analysis ? (
                               <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 flex items-center gap-4">
                                   <div className="text-xs font-mono px-2 py-1 bg-slate-200 rounded text-slate-600">
                                       Status: {scannedData.content_analysis.status.toUpperCase()}
                                   </div>
                                   <div className="text-xs text-slate-600 flex-1">
                                       {scannedData.content_analysis.notes}
                                   </div>
                                   {scannedData.content_analysis.score !== null && (
                                       <div className="text-sm font-bold text-emerald-600">
                                           Score: {scannedData.content_analysis.score} / 100
                                       </div>
                                   )}
                               </div>
                           ) : (
                               <div className="text-xs text-slate-400 italic">Not available for this scan mode.</div>
                           )}
                       </div>
                   </div>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <Card>
             <SectionHeader title="Supported File Types" />
             <div className="grid grid-cols-2 gap-2">
               {fileTypes.map((t) => (
                 <div key={t} className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-[12px] font-semibold text-slate-600 text-center hover:bg-sky-50 hover:border-sky-200 hover:text-sky-600 transition-colors cursor-default">
                   {t}
                 </div>
               ))}
             </div>
           </Card>

           <Card>
             <SectionHeader title="Today's Scan Stats" />
             <SidebarStat value="186"   label="Files Scanned" />
             <SidebarStat value="14"    label="Malicious Detected" accent />
             <SidebarStat value="7"     label="Quarantined" accent />
             <SidebarStat value="7,241" label="YARA Signatures Active" />
           </Card>

           <Card>
             <SectionHeader title="Detection by File Type" />
             <div className="space-y-2">
               {[{ t: 'PDF', pct: 45 }, { t: 'DOCX/XLSX', pct: 30 }, { t: 'EXE', pct: 20 }, { t: 'Other', pct: 5 }].map(({ t, pct }) => (
                 <div key={t} className="flex items-center gap-2">
                   <span className="text-[12px] text-slate-500 w-20">{t}</span>
                   <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                     <motion.div
                       className="h-full bg-gradient-to-r from-sky-400 to-sky-500 rounded-full"
                       initial={{ width: 0 }}
                       animate={{ width: `${pct}%` }}
                       transition={{ duration: 1, ease: [0.34, 1.2, 0.64, 1] }}
                     />
                   </div>
                   <span className="text-[11px] font-bold text-slate-600 w-7 text-right">{pct}%</span>
                 </div>
               ))}
             </div>
           </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
