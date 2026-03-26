import { motion } from 'framer-motion'
import {
  RiRobotFill, RiCheckDoubleLine, RiCloseCircleLine, RiTimeLine,
  RiDashboard2Line, RiPlayCircleLine,
} from 'react-icons/ri'
import {
  Card, StatCard, RiskBadge, PageWrapper, PageHeader, SectionHeader, Tag, ProgressBar,
} from '../../components/ui'

const recentTests = [
  { agent: 'Auto-Dev V3',        dev: 'amit.k',        status: 'Failed', vulnerabilities: 3, isolation: 100, time: '10m ago' },
  { agent: 'Customer Support',   dev: 'priya.s',       status: 'Passed', vulnerabilities: 0, isolation: 100, time: '2h ago' },
  { agent: 'Data Analyzer',      dev: 'rahul.v',       status: 'Passed', vulnerabilities: 0, isolation: 100, time: '5h ago' },
  { agent: 'Code Reviewer Beta', dev: 'deepa.i',       status: 'Failed', vulnerabilities: 1, isolation: 85,  time: '1d ago' },
  { agent: 'Marketing Gen',      dev: 'system_auto',   status: 'Passed', vulnerabilities: 0, isolation: 100, time: '1d ago' },
]

export default function SandboxMonitor() {
  return (
    <PageWrapper>
      <PageHeader
        title="Agent Sandbox Monitor"
        sub="Enterprise-wide oversight of AI Agent vulnerability testing, Docker container isolation, and system call monitoring."
      />

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard icon={RiRobotFill}       value="342" label="Total Agents Tested" change="12" changeDir="up" iconBg="bg-sky-50" iconColor="text-sky-500" />
        <StatCard icon={RiCheckDoubleLine} value="281" label="Passed Validation" change="8" changeDir="up" iconBg="bg-emerald-50" iconColor="text-emerald-500" />
        <StatCard icon={RiCloseCircleLine} value="61"  label="Failed (Vulnerable)" change="-2" changeDir="down" iconBg="bg-red-50" iconColor="text-red-500" />
        <StatCard icon={RiDashboard2Line}  value="100%" label="Isolation Activeness" change="0%" changeDir="up" iconBg="bg-indigo-50" iconColor="text-indigo-500" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <Card>
            <SectionHeader title="Recent Sandbox Executions" />
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="tbl-th">Agent Name</th>
                  <th className="tbl-th">Developer</th>
                  <th className="tbl-th">Status</th>
                  <th className="tbl-th">Vulns</th>
                  <th className="tbl-th">Isolation Score</th>
                  <th className="tbl-th">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentTests.map((test, i) => (
                  <motion.tr
                    key={i}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="border-b border-slate-50 last:border-none"
                  >
                    <td className="p-3 text-[12px] font-bold text-slate-700">{test.agent}</td>
                    <td className="p-3 text-[11px] font-mono text-slate-500">{test.dev}</td>
                    <td className="p-3">
                      <RiskBadge level={test.status === 'Passed' ? 'safe' : 'critical'}>{test.status}</RiskBadge>
                    </td>
                    <td className="p-3 text-[12px] font-bold text-slate-700">{test.vulnerabilities}</td>
                    <td className="p-3">
                      <div className="w-24">
                        <ProgressBar value={test.isolation} color={test.isolation === 100 ? 'emerald' : 'yellow'} />
                      </div>
                    </td>
                    <td className="p-3 text-[11px] text-slate-400">{test.time}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <SectionHeader title="Most Common Vulnerabilities" />
             <div className="space-y-3 pt-2">
              {[
                { name: 'Unrestricted File Read', count: 42, pct: 68 },
                { name: 'Network Exfiltration',   count: 15, pct: 24 },
                { name: 'Subprocess Spawning',    count: 12, pct: 19 },
                { name: 'Privilege Escalation',   count: 2,  pct: 3 },
              ].map(v => (
                <div key={v.name} className="flex flex-col gap-1.5">
                  <div className="flex justify-between items-center text-[11px]">
                    <span className="font-semibold text-slate-600">{v.name}</span>
                    <span className="font-bold text-red-500">{v.count} incidents</span>
                  </div>
                  <ProgressBar value={v.pct} color="red" />
                </div>
              ))}
            </div>
          </Card>
          
          <Card className="bg-slate-900 border-none">
            <div className="flex items-center gap-2 mb-3">
              <RiPlayCircleLine className="text-emerald-400 text-xl" />
              <h3 className="text-white font-semibold text-[13px]">Live Container Status</h3>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-[11px]">
                 <span className="text-slate-400">Active Test Containers</span>
                 <span className="text-emerald-400 font-bold">4 running</span>
              </div>
              <div className="flex justify-between text-[11px]">
                 <span className="text-slate-400">seccomp filters</span>
                 <span className="text-white">Active (strict mode)</span>
              </div>
              <div className="flex justify-between text-[11px]">
                 <span className="text-slate-400">AppArmor profiles</span>
                 <span className="text-white">Enforced</span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </PageWrapper>
  )
}
