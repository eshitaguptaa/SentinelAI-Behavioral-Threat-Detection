import { useNavigate } from "react-router-dom";

import ExcelUploadZone from "../components/ExcelUploadZone";
import StatusRefreshButton from "../components/StatusRefreshButton";
import { useAnalysis } from "../contexts/AnalysisContext";
import styles from "./Dashboard.module.css";

export default function UploadPage() {
  const {
    loading,
    backendStatus,
    analyzeExcelFile,
    runSampleAnalysis,
  } = useAnalysis();
  const navigate = useNavigate();

  const offline = backendStatus === "offline";

  const afterLoad = async (ok: boolean) => {
    if (ok) navigate("/app/overview");
  };

  return (
    <div className={styles.pageFill}>
      <div className={styles.toolbar}>
        <div>
          <p className={styles.eyebrow}>Security operations</p>
          <h1 className={styles.pageTitle}>Upload</h1>
        </div>
        <div className={styles.actions}>
          <StatusRefreshButton />
        </div>
      </div>

      <section className={styles.introStage} aria-label="Import workbook">
        <div className={styles.introCopy}>
          <p className={styles.introEyebrow}>Begin analysis</p>
          <h2 className={styles.introHeadline}>Drop your Excel. See the risk.</h2>
          <div className={styles.introRule} />
          <p className={styles.introLead}>
            Bring a workbook of employee-day activity into SentinelAI — we score
            anomalies, rank risk, and open a clear path to investigate.
          </p>
          <ul className={styles.introPrompts}>
            <li>
              <span>01</span>
              Drop your file on the right
            </li>
            <li>
              <span>02</span>
              Or choose a file from your computer
            </li>
            <li>
              <span>03</span>
              Need a format? Grab the template
            </li>
            <li>
              <span>04</span>
              No file to upload? Click Sample data
            </li>
          </ul>
          {offline ? (
            <p className={styles.uploadHint}>API offline — start the backend first.</p>
          ) : null}
        </div>

        <div className={styles.introUpload}>
          <ExcelUploadZone
            disabled={loading || offline}
            onUpload={async (file) => {
              const ok = await analyzeExcelFile(file);
              await afterLoad(ok);
            }}
            onUseSample={async () => {
              const ok = await runSampleAnalysis();
              await afterLoad(ok);
            }}
          />
        </div>
      </section>
    </div>
  );
}
