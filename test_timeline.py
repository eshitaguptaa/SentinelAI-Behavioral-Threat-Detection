from synthetic_data import generate_enterprise, generate_behavior_profiles
from synthetic_data.generators.timeline_generator import generate_workday_timelines
from datetime import date
# Generate enterprise
enterprise = generate_enterprise()

# Generate behavior profiles
profiles = generate_behavior_profiles(
    enterprise.employees,
    enterprise.resources,
    locations=enterprise.locations,
    departments_by_id={d.department_id: d.name for d in enterprise.departments},
)

# Generate one day of events
events = generate_workday_timelines(
    employees=enterprise.employees,
    profiles=profiles,
    devices=enterprise.devices,
    work_date=date.today()
)

print("=" * 120)
print("TIMELINE GENERATION VERIFICATION")
print("=" * 120)

print(f"\nTotal Events Generated : {len(events)}")

# Sort by employee then timestamp
events = sorted(events, key=lambda e: (e.employee_id, e.timestamp))

current_employee = None
employees_shown = 0

for event in events:

    if event.employee_id != current_employee:

        employees_shown += 1
        if employees_shown > 5:
            break

        current_employee = event.employee_id

        print("\n" + "=" * 120)
        print(f"Employee : {event.employee_id}")
        print("=" * 120)

    resource = getattr(event, "resource_id", None)

    print(
        f"{event.timestamp} | "
        f"{event.event_type:<20} | "
        f"{resource}"
    )