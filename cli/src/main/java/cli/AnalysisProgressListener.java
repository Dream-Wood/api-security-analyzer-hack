package cli;

/**
 * Интерфейс слушателя для отслеживания прогресса анализа и логирования.
 * Реализации могут использовать этот интерфейс для обновления UI, записи логов или отслеживания метрик.
 *
 * <p>Этот интерфейс предоставляет три основных метода для мониторинга процесса анализа:
 * <ul>
 *   <li>{@link #onLog(String, String)} - для записи произвольных сообщений логирования</li>
 *   <li>{@link #onPhaseChange(String, int)} - для отслеживания смены фаз анализа</li>
 *   <li>{@link #onStepComplete(int, String)} - для отслеживания завершения отдельных шагов</li>
 * </ul>
 *
 * @author API Security Analyzer Team
 * @since 1.0
 */
public interface AnalysisProgressListener {

    /**
     * Вызывается при генерации сообщения лога.
     *
     * @param level уровень логирования (INFO, WARNING, ERROR и т.д.)
     * @param message сообщение лога
     */
    void onLog(String level, String message);

    /**
     * Вызывается при изменении фазы анализа.
     * Фазы могут включать: парсинг, аутентификацию, сканирование, анализ.
     *
     * @param phase текущая фаза анализа
     * @param totalSteps общее количество шагов в данной фазе анализа
     */
    void onPhaseChange(String phase, int totalSteps);

    /**
     * Вызывается при завершении шага анализа.
     *
     * @param stepNumber номер текущего шага (начиная с 1)
     * @param message описание завершенного шага
     */
    void onStepComplete(int stepNumber, String message);

    /**
     * Возвращает реализацию по умолчанию, которая не выполняет никаких действий.
     * Используется когда не требуется отслеживание прогресса.
     *
     * @return no-op реализация интерфейса
     */
    static AnalysisProgressListener noOp() {
        return new AnalysisProgressListener() {
            @Override
            public void onLog(String level, String message) {
                // No-op
            }

            @Override
            public void onPhaseChange(String phase, int totalSteps) {
                // No-op
            }

            @Override
            public void onStepComplete(int stepNumber, String message) {
                // No-op
            }
        };
    }
}
