import { useRef, useState, type DragEvent, type KeyboardEvent } from "react";
import { Download, Play, Upload } from "lucide-react";

import { downloadDemoSampleWorkbook } from "../services/api";
import styles from "../pages/Dashboard.module.css";

interface ExcelUploadZoneProps {
  disabled?: boolean;
  sourceFileName?: string | null;
  onUpload: (file: File) => void | Promise<unknown>;
  onUseSample?: () => void | Promise<unknown>;
}

export default function ExcelUploadZone({
  disabled = false,
  sourceFileName = null,
  onUpload,
  onUseSample,
}: ExcelUploadZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const dragDepth = useRef(0);

  const acceptFile = (file: File | undefined) => {
    if (!file || disabled) return;
    void onUpload(file);
  };

  const openPicker = () => {
    if (disabled) return;
    inputRef.current?.click();
  };

  const onDragEnter = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (disabled) return;
    dragDepth.current += 1;
    setDragging(true);
  };

  const onDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDragging(false);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    dragDepth.current = 0;
    setDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const onZoneKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openPicker();
    }
  };

  return (
    <div className={styles.uploadBlock}>
      <div
        className={`${styles.uploadZone} ${dragging ? styles.uploadZoneActive : ""} ${disabled ? styles.uploadZoneDisabled : ""}`}
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Drop an Excel file here, or click to choose a file"
        aria-disabled={disabled}
        onClick={openPicker}
        onKeyDown={onZoneKeyDown}
        onDragEnter={onDragEnter}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <div className={styles.uploadHero}>
          <span className={styles.uploadGlyph} aria-hidden>
            <Upload size={20} strokeWidth={1.85} />
          </span>
          <p className={styles.uploadTitle}>Drop Excel here</p>
          <p className={styles.uploadHint}>xlsx · xls · csv</p>
          <p className={styles.uploadCue}>
            {dragging ? "Release to upload" : "or click anywhere in this area"}
          </p>
        </div>

        <div
          className={styles.uploadActions}
          onClick={(event) => event.stopPropagation()}
          onKeyDown={(event) => event.stopPropagation()}
        >
          <button
            type="button"
            className={styles.uploadPrimary}
            disabled={disabled}
            onClick={openPicker}
          >
            <Upload size={14} aria-hidden />
            Choose file
          </button>
          {onUseSample ? (
            <>
              <button
                type="button"
                className={styles.uploadGhost}
                disabled={disabled}
                title="Download the exact Excel workbook used by Run sample"
                onClick={() => downloadDemoSampleWorkbook()}
              >
                <Download size={14} aria-hidden />
                Download sample
              </button>
              <button
                type="button"
                className={styles.uploadGhost}
                disabled={disabled}
                title="Analyse the built-in sample batch"
                onClick={() => void onUseSample()}
              >
                <Play size={14} aria-hidden />
                Run sample
              </button>
            </>
          ) : null}
        </div>

        <input
          ref={inputRef}
          type="file"
          accept=".xlsx,.xls,.csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,text/csv"
          hidden
          onChange={(event) => {
            acceptFile(event.target.files?.[0]);
            event.currentTarget.value = "";
          }}
        />
      </div>
      {sourceFileName ? (
        <p className={styles.sourceMeta}>
          Loaded: <strong>{sourceFileName}</strong>
        </p>
      ) : null}
    </div>
  );
}
